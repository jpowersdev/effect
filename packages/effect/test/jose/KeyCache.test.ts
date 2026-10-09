import { assert, describe, it } from "@effect/vitest"
import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebSignature } from "effect/jose"
import * as TestClock from "effect/testing/TestClock"
import { WebCrypto } from "./utils.ts"

/** A Crypto service that counts JWK imports. */
const counting = () => {
  const counter = { imports: 0 }
  const crypto = Crypto.Crypto.of({
    ...WebCrypto,
    importKey: ((format: any, data: any, algorithm: any, options: any) => {
      if (format === "jwk") counter.imports++
      return WebCrypto.importKey(format, data, algorithm, options)
    }) as Crypto.Crypto["importKey"]
  })
  return { counter, crypto }
}

const fixture = Effect.gen(function*() {
  const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
  const json = JSON.stringify(yield* JsonWebKey.exportJwk(publicKey))
  const token = yield* JsonWebSignature.signCompact("x", { key: privateKey, protectedHeader: { alg: "ES256" } })
  return { json, token }
}).pipe(Effect.provideService(Crypto.Crypto, WebCrypto))

describe("JsonWebKey.KeyCache", () => {
  it.effect("imports a JWK on every call by default", () =>
    Effect.gen(function*() {
      const { json, token } = yield* fixture
      const { counter, crypto } = counting()
      for (let i = 0; i < 3; i++) {
        yield* JsonWebSignature.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] }).pipe(
          Effect.provideService(Crypto.Crypto, crypto)
        )
      }
      assert.strictEqual(counter.imports, 3)
    }))

  it.effect("imports once per JWK, algorithm, and operation with layerKeyCache", () =>
    Effect.gen(function*() {
      const { json, token } = yield* fixture
      const { counter, crypto } = counting()
      yield* Effect.gen(function*() {
        // Fresh objects parsed from JSON each time still hit the cache.
        for (let i = 0; i < 3; i++) {
          yield* JsonWebSignature.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        }
        assert.strictEqual(counter.imports, 1)
        // Reordered members are the same key.
        const reordered = Object.fromEntries(Object.entries(JSON.parse(json)).reverse())
        yield* JsonWebSignature.verifyCompact(token, reordered as JsonWebKey.Jwk, { algorithms: ["ES256"] })
        assert.strictEqual(counter.imports, 1)
      }).pipe(
        Effect.provide(JsonWebKey.layerKeyCache({ capacity: 10 })),
        Effect.provideService(Crypto.Crypto, crypto)
      )
    }))

  it.effect("does not cache failed imports and honours timeToLive", () =>
    Effect.gen(function*() {
      const { json, token } = yield* fixture
      const { counter, crypto } = counting()
      const broken = { ...JSON.parse(json), x: "AAAA" }
      yield* Effect.gen(function*() {
        for (let i = 0; i < 2; i++) {
          const error = yield* Effect.flip(JsonWebSignature.verifyCompact(token, broken, { algorithms: ["ES256"] }))
          assert.strictEqual(error._tag, "MalformedKeyError")
        }
        assert.strictEqual(counter.imports, 2)
        yield* JsonWebSignature.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        yield* JsonWebSignature.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        assert.strictEqual(counter.imports, 3)
        yield* TestClock.adjust("2 minutes")
        yield* JsonWebSignature.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        assert.strictEqual(counter.imports, 4)
      }).pipe(
        Effect.provide(JsonWebKey.layerKeyCache({ capacity: 10, timeToLive: "1 minute" })),
        Effect.provideService(Crypto.Crypto, crypto)
      )
    }).pipe(Effect.provide(TestClock.layer())))
})
