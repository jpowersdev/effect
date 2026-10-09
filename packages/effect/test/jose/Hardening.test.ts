import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import * as HttpClient from "effect/http/HttpClient"
import * as HttpClientResponse from "effect/http/HttpClientResponse"
import { JsonWebEncryption, JsonWebKey, JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import * as Layer from "effect/Layer"
import * as Redacted from "effect/Redacted"
import * as Schema from "effect/Schema"
import * as TestClock from "effect/testing/TestClock"
import { CryptoLive, text, utf8 } from "./utils.ts"

const secret = utf8("a-string-secret-at-least-256-bits-long")

const serving = (body: unknown, options?: { readonly url?: string }) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.sync(() => {
        const response = new Response(typeof body === "string" ? body : JSON.stringify(body))
        if (options?.url !== undefined) Object.defineProperty(response, "url", { value: options.url })
        return HttpClientResponse.fromWeb(request, response)
      })
    )
  )

describe("remote key set hardening", () => {
  it.effect("rejects insecure or ambiguous URLs before fetching", () =>
    Effect.gen(function*() {
      for (
        const url of [
          "http://issuer.example/jwks",
          "https://user:pass@issuer.example/jwks",
          "https://issuer.example/jwks#keys",
          "not a url"
        ]
      ) {
        const error = yield* Effect.flip(JsonWebKeySet.makeRemote(url))
        assert.strictEqual(error._tag, "InvalidKeySetUrlError", url)
      }
      yield* JsonWebKeySet.makeRemote("http://localhost:8080/jwks", { allowInsecureHttp: true })
      yield* JsonWebKeySet.makeRemote("https://issuer.example/jwks")
    }).pipe(Effect.provide(serving({ keys: [] }))))

  const tokenFor = Effect.gen(function*() {
    const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
    const jwk = { ...(yield* JsonWebKey.exportJwk(publicKey)), kid: "k" }
    const token = yield* JsonWebSignature.signCompact("x", {
      key: privateKey,
      protectedHeader: { alg: "ES256", kid: "k" }
    })
    return { jwk, token }
  })

  it.effect("refuses responses from a different URL (redirects)", () =>
    Effect.gen(function*() {
      const { jwk, token } = yield* tokenFor
      const error = yield* Effect.flip(
        Effect.flatMap(
          JsonWebKeySet.makeRemote("https://issuer.example/jwks"),
          (resolver) => JsonWebSignature.verifyCompact(token, resolver, { algorithms: ["ES256"] })
        ).pipe(Effect.provide(serving({ keys: [jwk] }, { url: "https://attacker.example/jwks" })))
      )
      assert.strictEqual(error._tag, "KeySetFetchError")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("caps the response size and the number of keys", () =>
    Effect.gen(function*() {
      const { jwk, token } = yield* tokenFor
      const verifyWith = (body: unknown, options: JsonWebKeySet.RemoteOptions) =>
        Effect.flatMap(
          JsonWebKeySet.makeRemote("https://issuer.example/jwks", options),
          (resolver) => JsonWebSignature.verifyCompact(token, resolver, { algorithms: ["ES256"] })
        ).pipe(Effect.provide(serving(body)))
      const padded = { keys: [jwk], padding: "x".repeat(200_000) }
      const big = yield* Effect.flip(verifyWith(padded, {}))
      assert.strictEqual(big._tag, "KeySetTooLargeError")
      const many = yield* Effect.flip(verifyWith({ keys: Array.from({ length: 3 }, () => jwk) }, { maxKeys: 2 }))
      assert.strictEqual(many._tag, "KeySetTooLargeError")
      // Raising the limit accepts the same response.
      yield* verifyWith(padded, { maxResponseBytes: 300_000 })
    }).pipe(Effect.provide(CryptoLive)))
})

describe("token size limits", () => {
  it.effect("rejects oversized compact tokens before parsing, with an override", () =>
    Effect.gen(function*() {
      const jws = Redacted.value(
        yield* JsonWebSignature.signCompact("x".repeat(70_000), { key: secret, protectedHeader: { alg: "HS256" } })
      )
      const tooLarge = yield* Effect.flip(JsonWebSignature.verifyCompact(jws, secret, { algorithms: ["HS256"] }))
      assert.strictEqual(tooLarge._tag, "JwsTooLargeError")
      yield* JsonWebSignature.verifyCompact(jws, secret, { algorithms: ["HS256"], maxTokenLength: 200_000 })
      const jwtTooLarge = yield* Effect.flip(JsonWebToken.verify("a".repeat(70_000), secret, { algorithms: ["HS256"] }))
      assert.strictEqual(jwtTooLarge._tag, "JwsTooLargeError")
      const jweTooLarge = yield* Effect.flip(JsonWebEncryption.decryptCompact("a".repeat(70_000), secret))
      assert.strictEqual(jweTooLarge._tag, "JweTooLargeError")
    }).pipe(Effect.provide(CryptoLive)))
})

describe("minimum HMAC key length (RFC 7518 section 3.2)", () => {
  it.effect("requires keys at least as long as the hash", () =>
    Effect.gen(function*() {
      for (const [alg, bytes] of [["HS256", 32], ["HS384", 48], ["HS512", 64]] as const) {
        const short = yield* Effect.flip(
          JsonWebSignature.signCompact("x", { key: new Uint8Array(bytes - 1), protectedHeader: { alg } })
        )
        assert.strictEqual(short._tag, "InvalidKeyError", alg)
        const token = yield* JsonWebSignature.signCompact("x", { key: new Uint8Array(bytes), protectedHeader: { alg } })
        const verifyShort = yield* Effect.flip(
          JsonWebSignature.verifyCompact(token, new Uint8Array(bytes - 1), { algorithms: [alg] })
        )
        assert.strictEqual(verifyShort._tag, "InvalidKeyError", alg)
      }
    }).pipe(Effect.provide(CryptoLive)))
})

describe("Redacted and branded tokens", () => {
  it.effect("returns tokens Redacted and branded, and accepts Redacted tokens and keys", () =>
    Effect.gen(function*() {
      const token = yield* JsonWebToken.sign({ sub: "u" }, {
        key: Redacted.make(secret),
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256" }
      })
      assert.isTrue(Redacted.isRedacted(token))
      assert.strictEqual(String(token), "<redacted>")
      assert.strictEqual(
        Redacted.value(token),
        yield* Schema.decodeUnknownEffect(JsonWebToken.Signed)(Redacted.value(token))
      )
      const { payload } = yield* JsonWebToken.verify(token, Redacted.make(secret), { algorithms: ["HS256"] })
      assert.strictEqual(payload.sub, "u")
      const header = yield* JsonWebSignature.decodeProtectedHeader(token)
      assert.strictEqual(header.alg, "HS256")
      const jwe = yield* JsonWebEncryption.encryptCompact("x", {
        key: new Uint8Array(32),
        protectedHeader: { alg: "dir", enc: "A256GCM" }
      })
      yield* Schema.decodeUnknownEffect(JsonWebEncryption.Compact)(Redacted.value(jwe))
      const { plaintext } = yield* JsonWebEncryption.decryptCompact(jwe, new Uint8Array(32))
      assert.strictEqual(text(plaintext), "x")
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("schema errors do not include the claims", () =>
    Effect.gen(function*() {
      const Claims = Schema.Struct({ role: Schema.Literals(["admin"]) })
      const token = yield* JsonWebToken.sign({ role: "top-secret-value" }, {
        key: secret,
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256" }
      })
      const error = yield* Effect.flip(JsonWebToken.verify(token, secret, { algorithms: ["HS256"], schema: Claims }))
      assert.strictEqual(error._tag, "ClaimValidationError")
      assert.notInclude(String((error as any).cause), "top-secret-value")
    }).pipe(Effect.provide(CryptoLive)))
})

describe("claims schema on signing", () => {
  const Claims = Schema.Struct({
    ...JsonWebToken.RegisteredClaims.fields,
    level: Schema.NumberFromString
  })

  it.effect("encodes typed claims with the schema and decodes them back", () =>
    Effect.gen(function*() {
      const token = yield* JsonWebToken.sign({ sub: "u", level: 3 }, {
        key: secret,
        expirationTime: "1 hour",
        protectedHeader: { alg: "HS256" },
        schema: Claims
      })
      const wire = yield* JsonWebToken.decodeUnverified(token)
      assert.strictEqual(wire.level, "3")
      const { payload } = yield* JsonWebToken.verify(token, secret, { algorithms: ["HS256"], schema: Claims })
      assert.strictEqual(payload.level, 3)
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("rejects claims that do not match the schema", () =>
    Effect.gen(function*() {
      const error = yield* Effect.flip(
        JsonWebToken.sign({ sub: 1 as unknown as string, level: 3 }, {
          key: secret,
          expirationTime: "1 hour",
          protectedHeader: { alg: "HS256" },
          schema: Claims
        })
      )
      assert.strictEqual(error._tag, "ClaimValidationError")
    }).pipe(Effect.provide(CryptoLive)))
})

describe("expiration required by default", () => {
  it.effect("verify rejects tokens without exp unless requireExpiration is false", () =>
    Effect.gen(function*() {
      const token = yield* JsonWebToken.sign({ sub: "u" }, {
        key: secret,
        protectedHeader: { alg: "HS256" },
        requireExpiration: false
      })
      const error = yield* Effect.flip(JsonWebToken.verify(token, secret, { algorithms: ["HS256"] }))
      assert(error._tag === "ClaimValidationError")
      assert.strictEqual(error.claim, "exp")
      assert.strictEqual(error.check, "missing")
      yield* JsonWebToken.verify(token, secret, { algorithms: ["HS256"], requireExpiration: false })
    }).pipe(Effect.provide(CryptoLive)))

  it.effect("sign requires an expiration unless requireExpiration is false", () =>
    Effect.gen(function*() {
      const error = yield* Effect.flip(
        JsonWebToken.sign({ sub: "u" }, { key: secret, protectedHeader: { alg: "HS256" } })
      )
      assert(error._tag === "ClaimValidationError")
      assert.strictEqual(error.claim, "exp")
      yield* JsonWebToken.sign({ sub: "u", exp: 2_000_000_000 }, { key: secret, protectedHeader: { alg: "HS256" } })
    }).pipe(Effect.provide(CryptoLive)))
})

describe("algorithms required for keys that do not pin one", () => {
  it.effect("is optional with a Crypto.Key and a defect when missing otherwise", () =>
    Effect.gen(function*() {
      const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256")
      const token = yield* JsonWebSignature.signCompact("x", { key: privateKey, protectedHeader: { alg: "ES256" } })
      yield* JsonWebSignature.verifyCompact(token, publicKey)
      const verifyUntyped = JsonWebSignature.verifyCompact as (
        ...args: ReadonlyArray<unknown>
      ) => Effect.Effect<unknown>
      const exit = yield* Effect.exit(verifyUntyped(token, secret))
      assert.isTrue(exit._tag === "Failure" && String(exit.cause).includes("algorithms"))
    }).pipe(Effect.provide(CryptoLive)))
})

describe("remote key set freshness", () => {
  it.effect("honours Cache-Control max-age below cacheMaxAge, and refresh fetches on demand", () =>
    Effect.gen(function*() {
      const { privateKey, publicKey } = yield* JsonWebKey.generateKeyPair("ES256", { extractable: true })
      const jwk = { ...(yield* JsonWebKey.exportJwk(publicKey)), kid: "k" }
      const token = yield* JsonWebSignature.signCompact("x", {
        key: privateKey,
        protectedHeader: { alg: "ES256", kid: "k" }
      })
      let requests = 0
      const http = Layer.succeed(
        HttpClient.HttpClient,
        HttpClient.make((request) =>
          Effect.sync(() => {
            requests++
            return HttpClientResponse.fromWeb(
              request,
              new Response(JSON.stringify({ keys: [jwk] }), { headers: { "cache-control": "public, max-age=60" } })
            )
          })
        )
      )
      yield* Effect.gen(function*() {
        const keys = yield* JsonWebKeySet.makeRemote("https://issuer.example/jwks")
        yield* keys.refresh
        assert.strictEqual(requests, 1)
        yield* JsonWebSignature.verifyCompact(token, keys, { algorithms: ["ES256"] })
        assert.strictEqual(requests, 1)
        yield* TestClock.adjust("59 seconds")
        yield* JsonWebSignature.verifyCompact(token, keys, { algorithms: ["ES256"] })
        assert.strictEqual(requests, 1)
        yield* TestClock.adjust("2 seconds")
        yield* JsonWebSignature.verifyCompact(token, keys, { algorithms: ["ES256"] })
        assert.strictEqual(requests, 2)
      }).pipe(Effect.provide(http))
    }).pipe(Effect.provide([CryptoLive, TestClock.layer()])))
})
