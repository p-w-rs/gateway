// Sealing a typed secret to gated (PLAN-v4 phase 3, "Credential dialog").
//
// The Client field (field.tsx) calls seal() with the dialog's public key (an
// X25519 key gated made for this request and attempt; its private half never
// leaves gated) and the plaintext {rid, a, v}. NaCl's box (Curve25519,
// XSalsa20, Poly1305) under a fresh ephemeral key pair: only gated can open
// it, and it can't be altered unnoticed. The library is vendored TweetNaCl
// 1.0.3 (vendor/nacl-fast.js, audited, public domain; vendor/VENDOR.md has
// its npm integrity, the original sha256 and the one-line change that makes
// it an ES module). Mods have crypto.getRandomValues but no asymmetric
// WebCrypto (FEASIBILITY-v4 P1), so the PRNG is set here explicitly from
// crypto.getRandomValues, never left to the library's environment sniffing.
//
// No secret leaves this module unsealed: the plaintext bytes and the
// ephemeral secret key are overwritten before seal() returns. (A JS string
// can't be wiped: the field keeps the typed text as an array of characters
// that it overwrites, and only the UTF-8 bytes built here exist briefly.)
import nacl from './vendor/nacl-fast.js'

const QUOTA = 65536

export function setPrng(): void {
  nacl.setPRNG((x: Uint8Array, n: number) => {
    const v = new Uint8Array(n)
    for (let i = 0; i < n; i += QUOTA) crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)))
    for (let i = 0; i < n; i++) x[i] = v[i] as number
    v.fill(0)
  })
}
setPrng()

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function b64encode(u: Uint8Array): string {
  let out = ''
  for (let i = 0; i < u.length; i += 3) {
    const a = u[i] as number
    const b = i + 1 < u.length ? (u[i + 1] as number) : 0
    const c = i + 2 < u.length ? (u[i + 2] as number) : 0
    const n = (a << 16) | (b << 8) | c
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!
    out += i + 1 < u.length ? B64[(n >> 6) & 63]! : '='
    out += i + 2 < u.length ? B64[n & 63]! : '='
  }
  return out
}

export function b64decode(s: string): Uint8Array {
  const clean = s.replace(/=+$/, '')
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) throw new Error('not base64')
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4))
  let bits = 0
  let acc = 0
  let j = 0
  for (const ch of clean) {
    acc = (acc << 6) | B64.indexOf(ch)
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[j++] = (acc >> bits) & 255
    }
  }
  return out
}

export type Sealed = { epk: string; nonce: string; box: string }

// Seal `plain` to gated's public key (base64, 32 bytes). `plain` is
// overwritten (zeros) before this returns.
export function seal(pubB64: string, plain: Uint8Array): Sealed {
  const pub = b64decode(pubB64)
  if (pub.length !== nacl.box.publicKeyLength) {
    plain.fill(0)
    throw new Error('the dialog key is not an X25519 public key')
  }
  const eph = nacl.box.keyPair()
  const nonce = nacl.randomBytes(nacl.box.nonceLength)
  const box = nacl.box(plain, nonce, pub, eph.secretKey)
  plain.fill(0)
  eph.secretKey.fill(0)
  return { epk: b64encode(eph.publicKey), nonce: b64encode(nonce), box: b64encode(box) }
}

// The plaintext a dialog takes: {rid, a, v} as UTF-8 (gated checks rid and a
// against the dialog it opens the box for).
export function plaintext(rid: string, attempt: number, values: readonly string[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ rid, a: attempt, v: values }))
}

// For tests only: open a box (the test plays gated with its own key pair).
export function openForTest(sealed: Sealed, secretKey: Uint8Array): Uint8Array | null {
  return nacl.box.open(b64decode(sealed.box), b64decode(sealed.nonce), b64decode(sealed.epk), secretKey)
}

export function keyPairForTest(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return nacl.box.keyPair()
}
