import { assert, describe, it } from "@effect/vitest"
import * as Crypto from "effect/Crypto"
import * as Effect from "effect/Effect"
import { JsonWebKey, JsonWebSignature } from "effect/jose"
import * as TestClock from "effect/testing/TestClock"
import { JoseLive, WebCrypto } from "./utils.ts"

/** A JsonWebSignature service whose Crypto counts JWK imports. */
const counting = Effect.gen(function*() {
  const counter = { imports: 0 }
  const crypto = Crypto.Crypto.of({
    ...WebCrypto,
    importKey: ((format: any, data: any, algorithm: any, options: any) => {
      if (format === "jwk") counter.imports++
      return WebCrypto.importKey(format, data, algorithm, options)
    }) as Crypto.Crypto["importKey"]
  })
  const jws = yield* JsonWebSignature.make.pipe(Effect.provideService(Crypto.Crypto, crypto))
  return { counter, jws }
})

const fixture = Effect.gen(function*() {
  const keys = yield* JsonWebKey.JsonWebKey
  const jws = yield* JsonWebSignature.JsonWebSignature
  const { privateKey, publicKey } = yield* keys.generateKeyPair("ES256", { extractable: true })
  const json = JSON.stringify(yield* keys.exportJwk(publicKey))
  const token = yield* jws.signCompact("x", { key: privateKey, protectedHeader: { alg: "ES256" } })
  return { json, token }
}).pipe(Effect.provide(JoseLive))

describe("JsonWebKey.KeyCache", () => {
  it.effect("imports a JWK on every call by default", () =>
    Effect.gen(function*() {
      const { json, token } = yield* fixture
      const { counter, jws } = yield* counting
      for (let i = 0; i < 3; i++) {
        yield* jws.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
      }
      assert.strictEqual(counter.imports, 3)
    }))

  it.effect("imports once per JWK, algorithm, and operation with layerKeyCache", () =>
    Effect.gen(function*() {
      const { json, token } = yield* fixture
      const { counter, jws } = yield* counting
      // The service is built without a cache; the cache is read from the calling fiber.
      yield* Effect.gen(function*() {
        // Fresh objects parsed from JSON each time still hit the cache.
        for (let i = 0; i < 3; i++) {
          yield* jws.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        }
        assert.strictEqual(counter.imports, 1)
        // Reordered members are the same key.
        const reordered = Object.fromEntries(Object.entries(JSON.parse(json)).reverse())
        yield* jws.verifyCompact(token, reordered as JsonWebKey.Jwk, { algorithms: ["ES256"] })
        assert.strictEqual(counter.imports, 1)
      }).pipe(Effect.provide(JsonWebKey.layerKeyCache({ capacity: 10 })))
    }))

  it.effect("does not cache failed imports and honours timeToLive", () =>
    Effect.gen(function*() {
      const { json, token } = yield* fixture
      const { counter, jws } = yield* counting
      const broken = { ...JSON.parse(json), x: "AAAA" }
      yield* Effect.gen(function*() {
        for (let i = 0; i < 2; i++) {
          const error = yield* Effect.flip(jws.verifyCompact(token, broken, { algorithms: ["ES256"] }))
          assert.strictEqual(error._tag, "MalformedKeyError")
        }
        assert.strictEqual(counter.imports, 2)
        yield* jws.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        yield* jws.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        assert.strictEqual(counter.imports, 3)
        yield* TestClock.adjust("2 minutes")
        yield* jws.verifyCompact(token, JSON.parse(json), { algorithms: ["ES256"] })
        assert.strictEqual(counter.imports, 4)
      }).pipe(Effect.provide(JsonWebKey.layerKeyCache({ capacity: 10, timeToLive: "1 minute" })))
    }).pipe(Effect.provide(TestClock.layer())))
})
