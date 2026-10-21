# Vendored: TweetNaCl.js 1.0.3

The gateway dialog's private field (`../field.tsx`, through `../seal.ts`)
seals what the person types with NaCl's `box` (X25519, XSalsa20-Poly1305)
to the dialog's public key, which gated opens with PyNaCl (libsodium). The
mod runs inside Claude Code with no npm and no Node, so the library is
vendored here, unchanged but for its last line.

| | |
|---|---|
| package | `tweetnacl@1.0.3` (npm registry, public domain: `LICENSE.tweetnacl` is its `LICENSE`, byte for byte) |
| fetched with | `pixi exec --spec nodejs npm pack tweetnacl@1.0.3` (a scratch folder; nothing installed) |
| registry integrity | `sha512-6rt+RN7aOi1nGMyC4Xa5DdYiukl2UWCbcJft7YhxReBGQD7OAM8Pbxw6YMo4r2diNEA8FEmu32YOn9rhaiE5yw==` (npm shasum `ac0af71680458d8a6378d0d0d050ab1407d35596`) |
| tarball sha256 | `5f8dc49cb4483e206ba3ebb22abbccfc0218c59b60fc78cce24197ced5b9e102` |
| file taken | `package/nacl-fast.js` |
| its sha256 as published | `6bcd37a3b20dce913f82d4b23e4e2b661058b4b953df8a3f8c45d56ac4f72447` |
| sha256 here (after the change below) | `c2b4c66a6fa3b366c9c64e737621561ac2e6aff33ed620a75d20fbf42586b177` |
| `nacl-fast.d.ts` | written here: types for the parts the mod uses (`box`, `box.open`, `box.keyPair`, `randomBytes`, `setPRNG`) |

## The one change: an ES module export

The library ends by attaching itself to `module.exports` or `self.nacl`;
Claude Code loads a mod's files as ES modules (no `module`, no `self`
assumed), so the last line exports the object instead. Nothing else
changed:

```diff
--- nacl-fast.js.orig
+++ nacl-fast.js
@@ -2388,4 +2388,4 @@
   }
 })();
 
-})(typeof module !== 'undefined' && module.exports ? module.exports : (self.nacl = self.nacl || {}));
+})(naclExports = {}); var naclExports; export default naclExports;
```

## The random source is set explicitly

At load the library looks for `self.crypto.getRandomValues` or Node's
`require('crypto')`, neither of which a mod is promised. `seal.ts`
therefore calls `nacl.setPRNG` itself with `crypto.getRandomValues` (in
chunks of 65,536 bytes, its per-call limit) before any key pair or nonce is
made, and fails closed (nothing is sealed) if `crypto.getRandomValues` is
missing. The ephemeral key pair and the nonce of every seal come from it.

## Checking it

```sh
# in a scratch folder
pixi exec --spec nodejs npm pack tweetnacl@1.0.3 --json   # integrity as above
tar xzf tweetnacl-1.0.3.tgz
shasum -a 256 package/nacl-fast.js                         # 6bcd37a3...
diff package/nacl-fast.js <plugin>/hooks/mod/vendor/nacl-fast.js   # only the last line
```

`tests/test_mod.py` checks this file's two sha256 values against the
vendored file and that the diff is the one line (the original line is
recorded in the test). Updating the library means a new `npm pack`, the
same one-line change, and new values here and in the test.
