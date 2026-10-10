---
"effect": minor
"@effect/platform-browser": minor
"@effect/platform-deno": minor
"@effect/platform-node-shared": minor
---

Add key-based operations to the `Crypto` service (`importKey`, `exportKey`, `generateKey`, `sign`, `verify`, `encrypt`, `decrypt`, `deriveBits`, `wrapKey`, `unwrapKey`), backed by Web Crypto in the platform layers via `Crypto.makeKeyOperations`, and add the `effect/jose` modules: `JsonWebAlgorithm`, `JsonWebKey`, `JsonWebKeySet`, `JsonWebSignature`, `JsonWebEncryption`, and `JsonWebToken`, implementing JWS, JWE, JWK, JWKS, and JWT without dependencies. Modules that perform key operations are services whose layers require `Crypto`, so their operations have no requirements of their own. Each kind of failure is its own tagged error, defined in the module it relates to.
