import type { Crypto, Effect, Redacted } from "effect"
import type { HttpClient } from "effect/http"
import { JsonWebEncryption, JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import { describe, expect, it } from "tstyche"

declare const secret: Uint8Array
declare const cryptoKey: Crypto.Key

describe("token types", () => {
  it("produced tokens are Redacted and branded", () => {
    expect(JsonWebToken.sign({}, { key: secret, protectedHeader: { alg: "HS256" } })).type.toBe<
      Effect.Effect<Redacted.Redacted<JsonWebToken.Signed>, JsonWebToken.SignError, Crypto.Crypto>
    >()
    expect(JsonWebSignature.signCompact("x", { key: secret, protectedHeader: { alg: "HS256" } })).type.toBe<
      Effect.Effect<Redacted.Redacted<JsonWebSignature.Compact>, JsonWebSignature.SignError, Crypto.Crypto>
    >()
    expect(
      JsonWebEncryption.encryptCompact("x", { key: secret, protectedHeader: { alg: "dir", enc: "A256GCM" } })
    ).type.toBe<
      Effect.Effect<Redacted.Redacted<JsonWebEncryption.Compact>, JsonWebEncryption.EncryptError, Crypto.Crypto>
    >()
  })

  it("algorithms are closed sets", () => {
    expect(JsonWebSignature.signCompact).type.not.toBeCallableWith("x", {
      key: secret,
      protectedHeader: { alg: "none" }
    })
  })

  it("algorithms are required unless the key is a Crypto.Key", () => {
    expect(JsonWebSignature.verifyCompact).type.not.toBeCallableWith("token", secret)
    expect(JsonWebSignature.verifyCompact).type.toBeCallableWith("token", secret, { algorithms: ["HS256"] })
    expect(JsonWebSignature.verifyCompact).type.toBeCallableWith("token", cryptoKey)
    expect(JsonWebToken.verify).type.not.toBeCallableWith("token", secret, { issuer: "urn:iss" })
  })

  it("remote key sets fail at construction only for invalid URLs", () => {
    expect(JsonWebKeySet.makeRemote("https://issuer.example/jwks")).type.toBe<
      Effect.Effect<
        JsonWebKeySet.RemoteResolver<JsonWebKeySet.RemoteSelectError>,
        JsonWebKeySet.InvalidKeySetUrlError,
        HttpClient.HttpClient
      >
    >()
  })
})
