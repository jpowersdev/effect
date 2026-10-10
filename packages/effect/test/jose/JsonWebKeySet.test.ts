import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import * as HttpClient from "effect/http/HttpClient"
import * as HttpClientResponse from "effect/http/HttpClientResponse"
import { JsonWebKey, JsonWebKeySet, JsonWebSignature } from "effect/jose"
import * as Layer from "effect/Layer"
import * as KeyValueStore from "effect/persistence/KeyValueStore"
import * as Redacted from "effect/Redacted"
import * as TestClock from "effect/testing/TestClock"
import { JoseLive } from "./utils.ts"

const keySetWithoutKids = Effect.gen(function*() {
  const keys = yield* JsonWebKey.JsonWebKey
  const jws = yield* JsonWebSignature.JsonWebSignature
  const a = yield* keys.generateKeyPair("ES256", { extractable: true })
  const b = yield* keys.generateKeyPair("ES256", { extractable: true })
  const jwks = { keys: [yield* keys.exportJwk(a.publicKey), yield* keys.exportJwk(b.publicKey)] }
  const token = yield* jws.signCompact("x", { key: b.privateKey, protectedHeader: { alg: "ES256" } })
  return { jwks, token }
})

const serving = (body: () => unknown, onRequest: () => void) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.sync(() => {
        onRequest()
        return HttpClientResponse.fromWeb(request, new Response(JSON.stringify(body())))
      })
    )
  )

describe("JsonWebKeySet", () => {
  it.effect("fails on several matching keys unless tryEach is chosen", () =>
    Effect.gen(function*() {
      const keySets = yield* JsonWebKeySet.JsonWebKeySet
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { jwks, token } = yield* keySetWithoutKids
      const strict = yield* keySets.makeLocal(jwks)
      const error = yield* Effect.flip(jws.verifyCompact(token, strict, { algorithms: ["ES256"] }))
      assert.strictEqual(error._tag, "MultipleMatchingKeysError")
      const tryEach = yield* keySets.makeLocal(jwks, { multipleMatches: "tryEach" })
      yield* jws.verifyCompact(token, tryEach, { algorithms: ["ES256"] })
    }).pipe(Effect.provide(JoseLive)))

  it.effect("tryEach still rejects tokens no candidate signed", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const keySets = yield* JsonWebKeySet.JsonWebKeySet
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { jwks } = yield* keySetWithoutKids
      const other = yield* keys.generateKeyPair("ES256")
      const token = yield* jws.signCompact("x", {
        key: other.privateKey,
        protectedHeader: { alg: "ES256" }
      })
      const resolver = yield* keySets.makeLocal(jwks, { multipleMatches: "tryEach" })
      const error = yield* Effect.flip(jws.verifyCompact(token, resolver, { algorithms: ["ES256"] }))
      assert.strictEqual(error._tag, "SignatureVerificationError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("persists remote key sets in a KeyValueStore", () =>
    Effect.gen(function*() {
      const keySets = yield* JsonWebKeySet.JsonWebKeySet
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { jwks, token } = yield* keySetWithoutKids
      let requests = 0
      const http = serving(() => jwks, () => requests++)
      const options = { storage: "keyValueStore", multipleMatches: "tryEach" } as const
      const verifyWithFreshResolver = Effect.gen(function*() {
        const resolver = yield* keySets.makeRemote("https://issuer.example/jwks", options)
        yield* jws.verifyCompact(token, resolver, { algorithms: ["ES256"] })
      }).pipe(Effect.provide(http))

      yield* verifyWithFreshResolver
      // A new resolver (a "restarted process") reuses the stored set.
      yield* verifyWithFreshResolver
      assert.strictEqual(requests, 1)
      const kv = yield* KeyValueStore.KeyValueStore
      assert.isTrue(yield* kv.has("effect/jose/JsonWebKeySet/https://issuer.example/jwks"))
      // Once the stored set is stale it is fetched again.
      yield* TestClock.adjust("11 minutes")
      yield* verifyWithFreshResolver
      assert.strictEqual(requests, 2)
      // A corrupt stored value is treated as missing.
      yield* kv.set("effect/jose/JsonWebKeySet/https://issuer.example/jwks", "not json")
      yield* verifyWithFreshResolver
      assert.strictEqual(requests, 3)
    }).pipe(Effect.provide([JoseLive, KeyValueStore.layerMemory, TestClock.layer()])))

  it.effect("memory storage does not require a KeyValueStore", () =>
    Effect.gen(function*() {
      const keySets = yield* JsonWebKeySet.JsonWebKeySet
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { token } = yield* keySetWithoutKids
      const resolver = yield* keySets.makeRemote("https://issuer.example/jwks", { multipleMatches: "tryEach" })
      yield* jws.verifyCompact(token, resolver, { algorithms: ["ES256"] })
    }).pipe(
      Effect.provide([JoseLive, serving(() => ({ keys: [] }), () => {})]),
      Effect.flip,
      Effect.map((e) =>
        // The served set is empty, so the point is only that this type-checks and runs without KeyValueStore.
        assert.strictEqual(e._tag, "NoMatchingKeyError")
      )
    ))
})

describe("JsonWebSignature.embeddedKey", () => {
  it.effect("verifies with the public key in the protected header", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { privateKey, publicKey } = yield* keys.generateKeyPair("ES256", { extractable: true })
      const jwk = yield* keys.exportJwk(publicKey)
      const token = yield* jws.signCompact("x", {
        key: privateKey,
        protectedHeader: { alg: "ES256", jwk }
      })
      const { protectedHeader } = yield* jws.verifyCompact(token, JsonWebSignature.embeddedKey, {
        algorithms: ["ES256"]
      })
      assert.deepStrictEqual(protectedHeader?.jwk, jwk)
    }).pipe(Effect.provide(JoseLive)))

  it.effect("rejects missing, unprotected, private, and symmetric embedded keys", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jws = yield* JsonWebSignature.JsonWebSignature
      const { privateKey, publicKey } = yield* keys.generateKeyPair("ES256", { extractable: true })
      const jwk = yield* keys.exportJwk(publicKey)
      const privateJwk = Redacted.value(yield* keys.exportPrivateJwk(privateKey))
      const cases: ReadonlyArray<Omit<JsonWebSignature.SignOptions, "key">> = [
        { protectedHeader: { alg: "ES256" } },
        { protectedHeader: { alg: "ES256" }, unprotectedHeader: { jwk } },
        { protectedHeader: { alg: "ES256", jwk: privateJwk } }
      ]
      for (const header of cases) {
        const signed = yield* jws.signFlattened("x", { key: privateKey, ...header })
        const error = yield* Effect.flip(
          jws.verifyFlattened(signed, JsonWebSignature.embeddedKey, { algorithms: ["ES256"] })
        )
        assert.strictEqual(error._tag, "MalformedJwsError")
      }
      const secret = new Uint8Array(32)
      const hmac = yield* jws.signCompact("x", {
        key: secret,
        protectedHeader: { alg: "HS256", jwk: { kty: "oct", k: "AAAA" } }
      })
      const error = yield* Effect.flip(
        jws.verifyCompact(hmac, JsonWebSignature.embeddedKey, { algorithms: ["HS256"] })
      )
      assert.strictEqual(error._tag, "MalformedJwsError")
    }).pipe(Effect.provide(JoseLive)))
})
