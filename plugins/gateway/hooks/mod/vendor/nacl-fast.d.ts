// Types for the parts of vendored TweetNaCl 1.0.3 (nacl-fast.js) the gate mod
// uses (see VENDOR.md). The library's own nacl.d.ts declares more.
declare const nacl: {
  box: {
    (message: Uint8Array, nonce: Uint8Array, theirPublicKey: Uint8Array, mySecretKey: Uint8Array): Uint8Array
    open(box: Uint8Array, nonce: Uint8Array, theirPublicKey: Uint8Array, mySecretKey: Uint8Array): Uint8Array | null
    keyPair(): { publicKey: Uint8Array; secretKey: Uint8Array }
    publicKeyLength: number
    nonceLength: number
  }
  randomBytes(n: number): Uint8Array
  setPRNG(fn: (x: Uint8Array, n: number) => void): void
}
export default nacl
