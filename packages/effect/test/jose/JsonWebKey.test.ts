import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebKeySet, JsonWebSignature } from "effect/jose"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import { JoseLive, utf8 } from "./utils.ts"

describe("JsonWebKey", () => {
  it.effect("computes the RFC 7638 example thumbprint", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jwk = {
        kty: "RSA",
        n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        e: "AQAB",
        alg: "RS256",
        kid: "2011-04-29"
      }
      assert.strictEqual(yield* keys.thumbprint(jwk), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("round-trips keys through JWK and PEM", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      for (const alg of ["RS256", "ES256", "EdDSA", "ECDH-ES"] as const) {
        const { privateKey, publicKey } = yield* keys.generateKeyPair(alg, { extractable: true })
        const jwk = yield* keys.exportJwk(publicKey)
        const imported = yield* keys.importJwk(jwk, alg)
        assert.deepStrictEqual(yield* keys.exportJwk(imported as any), jwk)
        const privateJwk = yield* keys.exportPrivateJwk(privateKey)
        assert.isTrue(Redacted.isRedacted(privateJwk))
        assert.strictEqual(String(privateJwk), "<redacted>")
        const notPublic = yield* Effect.flip(keys.exportJwk(privateKey))
        assert.strictEqual(notPublic._tag, "InvalidKeyError")
        const spki = yield* keys.exportSpki(publicKey)
        assert.match(spki, /^-----BEGIN PUBLIC KEY-----\n/)
        assert.strictEqual(spki, yield* Schema.decodeUnknownEffect(JsonWebKey.SpkiPem)(spki))
        const fromSpki = yield* keys.importSpki(spki, alg)
        assert.strictEqual(fromSpki.type, "public")
        const pkcs8 = yield* keys.exportPkcs8(privateKey)
        assert.isTrue(Redacted.isRedacted(pkcs8))
        const fromPkcs8 = yield* keys.importPkcs8(pkcs8, alg)
        assert.strictEqual(fromPkcs8.type, "private")
        assert.strictEqual(
          yield* keys.thumbprint(publicKey),
          yield* keys.thumbprint(yield* keys.exportPrivateJwk(privateKey))
        )
      }
    }).pipe(Effect.provide(JoseLive)))

  it.effect("returns oct keys as raw bytes", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const key = yield* keys.importJwk({ kty: "oct", k: "AQID" }, "HS256")
      assert.deepStrictEqual(key, new Uint8Array([1, 2, 3]))
    }).pipe(Effect.provide(JoseLive)))
})

describe("JsonWebKeySet", () => {
  it.effect("selects keys by kid and algorithm", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const keySets = yield* JsonWebKeySet.JsonWebKeySet
      const jws = yield* JsonWebSignature.JsonWebSignature
      const a = yield* keys.generateKeyPair("ES256", { extractable: true })
      const b = yield* keys.generateKeyPair("ES256", { extractable: true })
      const jwks = {
        keys: [
          { ...(yield* keys.exportJwk(a.publicKey)), kid: "a" },
          { ...(yield* keys.exportJwk(b.publicKey)), kid: "b" }
        ]
      }
      const resolver = yield* keySets.makeLocal(jwks)
      const token = yield* jws.signCompact("x", {
        key: b.privateKey,
        protectedHeader: { alg: "ES256", kid: "b" }
      })
      yield* jws.verifyCompact(token, resolver, { algorithms: ["ES256"] })
      const ambiguous = yield* jws.signCompact("x", {
        key: a.privateKey,
        protectedHeader: { alg: "ES256" }
      })
      const multiple = yield* Effect.flip(
        jws.verifyCompact(ambiguous, resolver, { algorithms: ["ES256"] })
      )
      assert.strictEqual(multiple._tag, "MultipleMatchingKeysError")
      const symmetric = yield* jws.signCompact("x", {
        key: utf8("s".repeat(32)),
        protectedHeader: { alg: "HS256" }
      })
      const unsupported = yield* Effect.flip(
        jws.verifyCompact(symmetric, resolver, { algorithms: ["HS256"] })
      )
      assert.strictEqual(unsupported._tag, "UnsupportedAlgorithmError")
    }).pipe(Effect.provide(JoseLive)))
})
