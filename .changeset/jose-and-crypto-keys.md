---
"effect": minor
"@effect/platform-browser": minor
"@effect/platform-deno": minor
"@effect/platform-node-shared": minor
---

Add key-based operations to the `Crypto` service (`importKey`, `exportKey`, `generateKey`, `sign`, `verify`, `encrypt`, `decrypt`, `deriveBits`, `wrapKey`, `unwrapKey`), backed by Web Crypto in the platform layers via `Crypto.makeKeyOperations`, and add the `effect/jose` modules: `JsonWebAlgorithm`, `JsonWebKey`, `JsonWebKeySet`, `JsonWebSignature`, `JsonWebEncryption`, `JsonWebToken`, and `JoseError`, implementing JWS, JWE, JWK, JWKS, and JWT without dependencies.
