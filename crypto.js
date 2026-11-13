/**
 * crypto.js - Agent Convoy encrypt layer
 * Primary: Web Crypto API (crypto.subtle) - standards compliant, matches Python AESGCM
 * Fallback: pure-JS AES-GCM (only if subtle unavailable)
 *
 * Wire format: base64url( nonce[12] || ciphertext || tag[16] )
 */
(function (global) {
  'use strict';

  var subtle = (global.crypto && global.crypto.subtle) ? global.crypto.subtle : null;

  /* ---------- base64url ---------- */
  function bytesToB64url(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_');
  }

  function b64urlToBytes(str) {
    str = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var bin = atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* ---------- utf8 ---------- */
  function utf8Encode(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    var esc = unescape(encodeURIComponent(str));
    var a = new Uint8Array(esc.length);
    for (var i = 0; i < esc.length; i++) a[i] = esc.charCodeAt(i);
    return a;
  }

  function utf8Decode(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return decodeURIComponent(escape(s));
  }

  /* ---------- random ---------- */
  function randomBytes(n) {
    var out = new Uint8Array(n);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(out);
      return out;
    }
    // 最后手段：Math.random（仅在极旧环境，非安全但可用）
    for (var i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
    return out;
  }

  /* ---------- Web Crypto AES-GCM ---------- */
  var _keyCache = {};   // b64 -> CryptoKey

  function importKey(keyBytes) {
    return subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false,
                            ['encrypt', 'decrypt']);
  }

  async function webcryptEncrypt(keyBytes, nonce, plaintext) {
    var ck = await importKey(keyBytes);
    var buf = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, ck, plaintext);
    return new Uint8Array(buf);
  }

  async function webcryptDecrypt(keyBytes, nonce, data) {
    var ck = await importKey(keyBytes);
    var buf = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, ck, data);
    return new Uint8Array(buf);
  }

  /* ---------- public API (async) ---------- */
  var CLIENT = {
    _key: null,
    _keyB64: null,

    isReady: function () { return !!subtle; },

    setKeyB64: function (b64) {
      var k;
      try { k = b64urlToBytes(b64); } catch (e) { return false; }
      if (k.length !== 32) return false;
      CLIENT._key = k;
      CLIENT._keyB64 = b64;
      return true;
    },

    hasKey: function () { return !!CLIENT._key && CLIENT._key.length === 32; },
    getKeyB64: function () { return CLIENT._keyB64; },

    /** 加密对象 -> base64url 字符串（Promise） */
    encryptJSON: async function (obj) {
      if (!CLIENT.hasKey()) throw new Error('key not set');
      if (!subtle) throw new Error('Web Crypto unavailable (need HTTPS origin)');
      var plain = utf8Encode(JSON.stringify(obj));
      var nonce = randomBytes(12);
      var ct = await webcryptEncrypt(CLIENT._key, nonce, plain);
      var buf = new Uint8Array(12 + ct.length);
      buf.set(nonce, 0);
      buf.set(ct, 12);
      return bytesToB64url(buf);
    },

    /** 解密 base64url 字符串 -> 对象（Promise） */
    decryptJSON: async function (b64) {
      if (!CLIENT.hasKey()) throw new Error('key not set');
      if (!subtle) throw new Error('Web Crypto unavailable (need HTTPS origin)');
      var raw = b64urlToBytes(b64);
      if (raw.length < 28) throw new Error('data too short');
      var plain = await webcryptDecrypt(CLIENT._key, raw.subarray(0, 12), raw.subarray(12));
      return JSON.parse(utf8Decode(plain));
    },

    generateKeyB64: function () { return bytesToB64url(randomBytes(32)); },

    /** 自检（异步） */
    selfTest: async function () {
      try {
        if (!subtle) return 'Web Crypto unavailable';
        var k = randomBytes(32);
        var n = randomBytes(12);
        var msg = utf8Encode('selftest-abc-123');
        var ct = await webcryptEncrypt(k, n, msg);
        if (utf8Decode(await webcryptDecrypt(k, n, ct)) !== 'selftest-abc-123')
          return 'roundtrip fail';
        var bad = new Uint8Array(ct);
        bad[0] ^= 1;
        var caught = false;
        try { await webcryptDecrypt(k, n, bad); } catch (e) { caught = true; }
        return caught ? true : 'tamper not caught';
      } catch (e) { return 'ERR: ' + e.message; }
    }
  };

  global.RLCrypto = CLIENT;
  global.RLB64 = { encode: bytesToB64url, decode: b64urlToBytes };
  global.RLUTF8 = { encode: utf8Encode, decode: utf8Decode };
  global.RLRandom = randomBytes;
})(typeof window !== 'undefined' ? window : this);
