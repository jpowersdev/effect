import type { Crypto, Effect, Redacted } from "effect"
import type { HttpClient } from "effect/http"
import { JsonWebEncryption, JsonWebKeySet, JsonWebSignature, JsonWebToken } from "effect/jose"
import { describe, expect, it } from "tstyche"

declare const secret: Uint8Array

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

  it("remote key sets fail at construction only for invalid URLs", () => {
    expect(JsonWebKeySet.makeRemote("https://issuer.example/jwks")).type.toBe<
      Effect.Effect<
        JsonWebKeySet.Resolver<JsonWebKeySet.RemoteSelectError>,
        JsonWebKeySet.InvalidKeySetUrlError,
        HttpClient.HttpClient
      >
    >()
  })
})
