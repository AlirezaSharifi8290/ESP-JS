'use strict';

const PASS_PTR = 4096;
const SALT_PTR = 8192;
const DATA_PTR = 16384;
const OUT_PTR = 12288;
let wasmPromise = null;

function hexToBytes(hex) {
  if (typeof hex !== 'string' || (hex.length & 1) || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

async function loadWasm() {
  if (!wasmPromise) {
    wasmPromise = fetch(new URL('./crypto.wasm', self.location.href), {cache:'force-cache'})
      .then(r => { if (!r.ok) throw new Error('Crypto module fetch failed'); return r.arrayBuffer(); })
      .then(bytes => WebAssembly.instantiate(bytes, {}));
  }
  return wasmPromise;
}

async function wasmCall(op, inputHex, saltHex, iterations) {
  const {instance} = await loadWasm();
  const memory = instance.exports.memory;
  const base = Number(instance.exports.memory_base());
  const view = new Uint8Array(memory.buffer);
  const input = op === 'derive' ? new TextEncoder().encode(inputHex) : hexToBytes(inputHex);
  const second = hexToBytes(saltHex);
  if (input.length > 512 || second.length > 256) throw new Error('Crypto input too large');
  const inputPtr = base + (op === 'derive' ? PASS_PTR : DATA_PTR);
  const secondPtr = base + SALT_PTR;
  const outPtr = base + OUT_PTR;
  view.set(input, inputPtr);
  view.set(second, secondPtr);
  let rc;
  if (op === 'derive') {
    rc = instance.exports.pbkdf2_export_entry(PASS_PTR, input.length, SALT_PTR, second.length, iterations, OUT_PTR);
  } else {
    rc = instance.exports.hmac_export_entry(SALT_PTR, second.length, DATA_PTR, input.length, OUT_PTR);
  }
  if (rc !== 0) throw new Error('Crypto operation failed');
  return view.slice(outPtr, outPtr + 32);
}

async function webCryptoDerive(password, salt, iterations) {
  if (!globalThis.crypto?.subtle) throw new Error('WASM crypto failed and Web Crypto is unavailable in this browser');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, key, 256);
  return new Uint8Array(bits);
}

async function derive(password, salt, iterations) {
  try {
    return await wasmCall('derive', String(password ?? ''), bytesToHex(salt), Number(iterations));
  } catch (wasmError) {
    return webCryptoDerive(String(password ?? ''), salt, Number(iterations));
  }
}

async function hmac(key, data) {
  try {
    return await wasmCall('hmac', bytesToHex(data), bytesToHex(key), 0);
  } catch (wasmError) {
    if (!globalThis.crypto?.subtle) throw wasmError;
    const cryptoKey = await crypto.subtle.importKey('raw', key, {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, data));
  }
}

self.onmessage = async (event) => {
  const {id, op} = event.data || {};
  try {
    let result;
    if (op === 'derive') {
      result = bytesToHex(await derive(event.data.password, hexToBytes(event.data.saltHex), Number(event.data.iterations)));
    } else if (op === 'hmac') {
      result = bytesToHex(await hmac(hexToBytes(event.data.keyHex), hexToBytes(event.data.dataHex)));
    } else {
      throw new Error('Unknown crypto operation');
    }
    self.postMessage({id, ok:true, result});
  } catch (error) {
    self.postMessage({id, ok:false, error:String(error?.message || error)});
  }
};
