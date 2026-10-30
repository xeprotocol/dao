/* XE DAO browser signer.
 *
 * Keys never leave the browser. A 32-byte ed25519 seed (hex) is held in sessionStorage for the tab
 * and imported into WebCrypto as PKCS8. Everything the server accepts is
 *   signature = ed25519( sha256( domain || 0x00 || canonical_json({payload, timestamp}) ) )
 * Routes that cost the sender something (the inbox) also want pow_nonce: a u64 such that
 *   sha256( nonce_le8 || signing_digest )[0:8], read big-endian, >= difficulty (from GET /v1/inbox).
 * with canonical_json = sorted keys, no whitespace, ASCII-escaped, timestamp in nanoseconds.
 *
 * If this browser cannot do Ed25519 in WebCrypto, every form still shows the exact bytes to sign
 * so a signature can be produced offline with `dao sign` and pasted in.
 */
(function () {
  const PKCS8_PREFIX = "302e020100300506032b657004220420";
  const enc = new TextEncoder();

  function hexToBytes(h) { h = h.trim().toLowerCase(); if (h.length % 2) throw new Error("odd hex"); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; }
  function bytesToHex(b) { return Array.from(b, x => x.toString(16).padStart(2, "0")).join(""); }
  function b64urlToBytes(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; }
  function concat(...arrs) { let n = 0; for (const a of arrs) n += a.length; const o = new Uint8Array(n); let p = 0; for (const a of arrs) { o.set(a, p); p += a.length; } return o; }

  // Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)
  function canon(v) {
    if (v === null || v === undefined) return "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "number") { if (!Number.isInteger(v)) throw new Error("floats are not allowed in signed payloads"); return String(v); }
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "string") return canonStr(v);
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => canonStr(k) + ":" + canon(v[k])).join(",") + "}";
  }
  function canonStr(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c === 0x22) out += '\\"';
      else if (c === 0x5c) out += "\\\\";
      else if (c === 0x0a) out += "\\n";
      else if (c === 0x0d) out += "\\r";
      else if (c === 0x09) out += "\\t";
      else if (c === 0x08) out += "\\b";
      else if (c === 0x0c) out += "\\f";
      else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
      else out += s[i];
    }
    return out + '"';
  }

  async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }

  function nowNs() { return (BigInt(Date.now()) * 1000000n).toString(); }

  function target(domain, payload, tsStr) {
    const body = '{"payload":' + canon(payload) + ',"timestamp":' + tsStr + "}";
    return concat(enc.encode(domain), new Uint8Array([0]), enc.encode(body));
  }

  const Signer = {
    supported: null,
    async detect() {
      if (this.supported !== null) return this.supported;
      try {
        const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
        await crypto.subtle.sign("Ed25519", kp.privateKey, new Uint8Array([1]));
        this.supported = true;
      } catch (e) { this.supported = false; }
      return this.supported;
    },
    hasKey() { return !!sessionStorage.getItem("xe_seed"); },
    async setSeed(hex) {
      const seed = hexToBytes(hex);
      if (seed.length !== 32) throw new Error("seed must be 32 bytes (64 hex)");
      const key = await crypto.subtle.importKey("pkcs8", concat(hexToBytes(PKCS8_PREFIX), seed), { name: "Ed25519" }, true, ["sign"]);
      const jwk = await crypto.subtle.exportKey("jwk", key);
      const pub = b64urlToBytes(jwk.x);
      const addr = bytesToHex(await sha256(concat(enc.encode("xe/account/v1"), pub)));
      sessionStorage.setItem("xe_seed", bytesToHex(seed));
      sessionStorage.setItem("xe_pub", bytesToHex(pub));
      sessionStorage.setItem("xe_addr", addr);
      return { pub_key: bytesToHex(pub), address: addr };
    },
    forget() { ["xe_seed", "xe_pub", "xe_addr"].forEach(k => sessionStorage.removeItem(k)); },
    pub() { return sessionStorage.getItem("xe_pub"); },
    addr() { return sessionStorage.getItem("xe_addr"); },
    async signBytes(bytes) {
      const seed = sessionStorage.getItem("xe_seed");
      if (!seed) throw new Error("no key loaded");
      const key = await crypto.subtle.importKey("pkcs8", concat(hexToBytes(PKCS8_PREFIX), hexToBytes(seed)), { name: "Ed25519" }, false, ["sign"]);
      return bytesToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", key, bytes)));
    },
    async signDigest(domain, payload) {
      const ts = nowNs();
      const digest = await sha256(target(domain, payload, ts));
      const sig = await this.signBytes(digest);
      return { ts, digest: bytesToHex(digest), signature: sig };
    },
    /** Proof of work over the signing digest; returns the nonce as decimal digits (u64, may exceed 2^53). */
    async pow(digestHex, difficultyHex, onProgress) {
      const diff = BigInt(difficultyHex);
      if (diff === 0n) return "0";
      const digest = hexToBytes(digestHex);
      const buf = new Uint8Array(8 + digest.length); buf.set(digest, 8);
      const view = new DataView(buf.buffer);
      let nonce = crypto.getRandomValues(new BigUint64Array(1))[0];
      for (let i = 0; ; i++) {
        view.setBigUint64(0, nonce, true);
        const h = await crypto.subtle.digest("SHA-256", buf);
        if (new DataView(h).getBigUint64(0, false) >= diff) return nonce.toString();
        nonce = (nonce + 1n) & 0xFFFFFFFFFFFFFFFFn;
        if (onProgress && (i & 0x3fff) === 0) onProgress(i);
      }
    },
    /** Build the body for a SignedRequest, with the timestamp (and nonce) as exact digits. */
    body(payload, ts, pub_key, signature, pow_nonce) {
      return '{"payload":' + JSON.stringify(payload) + ',"timestamp":' + ts + ',"pub_key":"' + pub_key + '","signature":"' + signature + '"'
        + (pow_nonce != null ? ',"pow_nonce":' + pow_nonce : "") + '}';
    },
    /** opts.pow: difficulty hex (does proof of work over the digest); opts.onProgress(hashes). */
    async post(url, domain, payload, manual, opts) {
      let ts, pub, sig, digest, nonce = null;
      if (manual && manual.signature) {
        ts = manual.ts; pub = manual.pub_key; sig = manual.signature; digest = manual.digest;
        if (manual.pow_nonce != null) nonce = manual.pow_nonce;
      } else {
        if (!this.hasKey()) throw new Error("load a key first, or sign offline");
        const r = await this.signDigest(domain, payload);
        ts = r.ts; pub = this.pub(); sig = r.signature; digest = r.digest;
      }
      if (opts && opts.pow && nonce == null) {
        if (!digest) digest = bytesToHex(await sha256(target(domain, payload, ts)));
        nonce = await this.pow(digest, opts.pow, opts.onProgress);
      }
      const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: this.body(payload, ts, pub, sig, nonce) });
      const text = await res.text();
      let data; try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
      if (!res.ok) throw new Error((data && (data.error || data.detail)) || ("HTTP " + res.status));
      return data;
    },
    /** For offline signing: show the digest a CLI must sign, for a fixed timestamp. */
    async offlineTarget(domain, payload) {
      const ts = nowNs();
      const digest = await sha256(target(domain, payload, ts));
      return { ts, digest: bytesToHex(digest), canonical: '{"payload":' + canon(payload) + ',"timestamp":' + ts + "}" };
    },
    hexToBytes, bytesToHex, canon,
  };

  window.XeSigner = Signer;

  // ---- tiny UI helpers -------------------------------------------------------------------
  window.$ = (s, r) => (r || document).querySelector(s);
  window.$$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  window.say = function (el, msg, ok) { el = typeof el === "string" ? $(el) : el; if (!el) return; el.textContent = msg; el.className = "msg " + (ok ? "ok" : "err"); el.hidden = false; };

  async function renderKeyBox() {
    const box = $("#keybox");
    if (!box) return;
    const ok = await Signer.detect();
    const status = $("#keystatus", box);
    if (Signer.hasKey()) {
      status.innerHTML = "Key loaded for this tab. Public key <code>" + Signer.pub() + "</code>, account <code>" + Signer.addr() + "</code>.";
      $("#keyform", box).hidden = true; $("#keyforget", box).hidden = false;
      if (window.onKeyLoaded) window.onKeyLoaded(Signer.pub(), Signer.addr());
    } else {
      status.textContent = ok ? "No key loaded. Paste a 64-hex ed25519 seed; it stays in this tab only." : "This browser cannot sign Ed25519 in WebCrypto. Use offline signing (dao sign) below each form.";
      $("#keyform", box).hidden = !ok; $("#keyforget", box).hidden = true;
    }
  }
  document.addEventListener("DOMContentLoaded", () => {
    renderKeyBox();
    const f = $("#keyform"); if (f) f.addEventListener("submit", async e => {
      e.preventDefault();
      try { await Signer.setSeed($("#seed").value); $("#seed").value = ""; await renderKeyBox(); }
      catch (err) { say("#keymsg", err.message, false); }
    });
    const forget = $("#keyforget"); if (forget) forget.addEventListener("click", () => { Signer.forget(); renderKeyBox(); });
  });
})();
