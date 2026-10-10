import type { Crypto, Effect, Redacted } from "effect"
import type { HttpClient } from "effect/http"
import type { JsonWebEncryption, JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import { describe, expect, it } from "tstyche"

declare const secret: Uint8Array
declare const cryptoKey: Crypto.Key
declare const jws: JsonWebSignature.JsonWebSignature
declare const jwe: JsonWebEncryption.JsonWebEncryption
declare const jwt: JsonWebToken.JsonWebToken
declare const keySets: JsonWebKeySet.JsonWebKeySet
declare const resolver: JsonWebKeySet.Resolver
declare const remoteResolver: JsonWebKeySet.RemoteResolver<JsonWebKeySet.RemoteSelectError>
declare const httpResolver: JsonWebSignature.KeyResolver<never, HttpClient.HttpClient>

describe("token types", () => {
  it("produced tokens are Redacted and branded", () => {
    expect(jwt.sign({}, { key: secret, protectedHeader: { alg: "HS256" } })).type.toBe<
      Effect.Effect<Redacted.Redacted<JsonWebToken.Signed>, JsonWebToken.SignError>
    >()
    expect(jws.signCompact("x", { key: secret, protectedHeader: { alg: "HS256" } })).type.toBe<
      Effect.Effect<Redacted.Redacted<JsonWebSignature.Compact>, JsonWebSignature.SignError>
    >()
    expect(
      jwe.encryptCompact("x", { key: secret, protectedHeader: { alg: "dir", enc: "A256GCM" } })
    ).type.toBe<
      Effect.Effect<Redacted.Redacted<JsonWebEncryption.Compact>, JsonWebEncryption.EncryptError>
    >()
  })

  it("algorithms are closed sets", () => {
    expect(jws.signCompact).type.not.toBeCallableWith("x", {
      key: secret,
      protectedHeader: { alg: "none" }
    })
  })

  it("algorithms are required unless the key is a Crypto.Key", () => {
    expect(jws.verifyCompact).type.not.toBeCallableWith("token", secret)
    expect(jws.verifyCompact).type.toBeCallableWith("token", secret, { algorithms: ["HS256"] })
    expect(jws.verifyCompact).type.toBeCallableWith("token", cryptoKey)
    expect(jwt.verify).type.not.toBeCallableWith("token", secret, { issuer: "urn:iss" })
    expect(jwt.verify).type.not.toBeCallableWith("token", resolver, { issuer: "urn:iss" })
    expect(jwt.verify).type.toBeCallableWith("token", resolver, { algorithms: ["ES256"], issuer: "urn:iss" })
  })

  it("remote key sets fail at construction only for invalid URLs", () => {
    expect(keySets.makeRemote("https://issuer.example/jwks")).type.toBe<
      Effect.Effect<
        JsonWebKeySet.RemoteResolver<JsonWebKeySet.RemoteSelectError>,
        JsonWebKeySet.InvalidKeySetUrlError,
        HttpClient.HttpClient
      >
    >()
  })
})

describe("service operations", () => {
  it("verifying against a key set requires no services", () => {
    expect(jwt.verify("token", resolver, { algorithms: ["ES256"], issuer: "urn:iss" })).type.toBe<
      Effect.Effect<JsonWebToken.Result<JsonWebToken.Claims>, JsonWebToken.VerifyError | JsonWebKeySet.SelectError>
    >()
    expect(jwt.verify("token", remoteResolver, { algorithms: ["ES256"] })).type.toBe<
      Effect.Effect<
        JsonWebToken.Result<JsonWebToken.Claims>,
        JsonWebToken.VerifyError | JsonWebKeySet.RemoteSelectError
      >
    >()
  })

  it("key resolvers keep their own requirements", () => {
    expect(jws.verifyCompact("token", httpResolver, { algorithms: ["ES256"] })).type.toBe<
      Effect.Effect<JsonWebSignature.VerifyResult, JsonWebSignature.VerifyError, HttpClient.HttpClient>
    >()
  })
})
