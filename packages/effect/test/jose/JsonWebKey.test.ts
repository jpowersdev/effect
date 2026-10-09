import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebKeySet, JsonWebSignature } from "effect/jose"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import { CryptoLive, utf8 } from "./utils.ts"

describe("JsonWebKey", () => {
  it.effect("computes the RFC 7638 example thumbprint", () =>
    Effect.gen(function*() {
      const jwk = {
        kty: "RSA",
        n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        e: "AQAB",
        alg: "RS256",
        kid: "2011-04-29"
      }
      assert.strictEqual(yield* JsonWebKey.thumbprint(jwk), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("round-trips keys through JWK and PEM", () =>
    Effect.gen(function*() {
      for (const alg of ["RS256", "ES256", "EdDSA", "ECDH-ES"] as const) {
        const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair(alg, { extractable: true })
        const jwk = yield* JsonWebKey.exportJwk(publicKey)
        const imported = yield* JsonWebKey.importJwk(jwk, alg)
        assert.deepStrictEqual(yield* JsonWebKey.exportJwk(imported as any), jwk)
        const privateJwk = yield* JsonWebKey.exportPrivateJwk(privateKey)
        assert.isTrue(Redacted.isRedacted(privateJwk))
        assert.strictEqual(String(privateJwk), "<redacted>")
        const notPublic = yield* Effect.flip(JsonWebKey.exportJwk(privateKey))
        assert.strictEqual(notPublic._tag, "InvalidKeyError")
        const spki = yield* JsonWebKey.exportSpki(publicKey)
        assert.match(spki, /^-----BEGIN PUBLIC KEY-----\n/)
        assert.strictEqual(spki, yield* Schema.decodeUnknownEffect(JsonWebKey.SpkiPem)(spki))
        const fromSpki = yield* JsonWebKey.importSpki(spki, alg)
        assert.strictEqual(fromSpki.type, "public")
        const pkcs8 = yield* JsonWebKey.exportPkcs8(privateKey)
        assert.isTrue(Redacted.isRedacted(pkcs8))
        const fromPkcs8 = yield* JsonWebKey.importPkcs8(pkcs8, alg)
        assert.strictEqual(fromPkcs8.type, "private")
        assert.strictEqual(
          yield* JsonWebKey.thumbprint(publicKey),
          yield* JsonWebKey.thumbprint(yield* JsonWebKey.exportPrivateJwk(privateKey))
        )
      }
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("returns oct keys as raw bytes", () =>
    Effect.gen(function*() {
      const key = yield* JsonWebKey.importJwk({ kty: "oct", k: "AQID" }, "HS256")
      assert.deepStrictEqual(key, new Uint8Array([1, 2, 3]))
    }).pipe(Effect.provide(CryptoLive)))
})

describe("JsonWebKeySet", () => {
  it.effect("selects keys by kid and algorithm", () =>
    Effect.gen(function*() {
      const a = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
      const b = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
      const jwks = {
        keys: [
          { ...(yield* JsonWebKey.exportJwk(a.publicKey)), kid: "a" },
          { ...(yield* JsonWebKey.exportJwk(b.publicKey)), kid: "b" }
        ]
      }
      const resolver = yield* JsonWebKeySet.makeLocal(jwks)
      const token = yield* JsonWebSignature.signCompact("x", {
        key: b.privateKey,
        protectedHeader: { alg: "ES256", kid: "b" }
      })
      yield* JsonWebSignature.verifyCompact(token, resolver)
      const ambiguous = yield* JsonWebSignature.signCompact("x", {
        key: a.privateKey,
        protectedHeader: { alg: "ES256" }
      })
      const multiple = yield* Effect.flip(JsonWebSignature.verifyCompact(ambiguous, resolver))
      assert.strictEqual(multiple._tag, "MultipleMatchingKeysError")
      const symmetric = yield* JsonWebSignature.signCompact("x", {
        key: utf8("s".repeat(32)),
        protectedHeader: { alg: "HS256" }
      })
      const unsupported = yield* Effect.flip(JsonWebSignature.verifyCompact(symmetric, resolver))
      assert.strictEqual(unsupported._tag, "UnsupportedAlgorithmError")
    }).pipe(Effect.provide(CryptoLive)))
})
