import type { Effect } from "effect"
import type { HttpClient } from "effect/http"
import type { JsonWebKeySet, JsonWebSignature } from "effect/jose"
import type { KeyValueStore } from "effect/persistence"
import { describe, expect, it } from "tstyche"

declare const keySets: JsonWebKeySet.JsonWebKeySet
declare const jwks: JsonWebKeySet.JwkSet

type Services<T> = T extends Effect.Effect<infer _A, infer _E, infer R> ? R : never
type ResolverError<T> = T extends Effect.Effect<JsonWebKeySet.Resolver<infer E>, infer _E, infer _R> ? E : never
type ResolverServices<T> = T extends Effect.Effect<infer A, infer _E, infer _R> ? JsonWebSignature.ResolverServices<A>
  : never

describe("JsonWebKeySet.makeLocal", () => {
  it("returns a resolver that requires no services", () => {
    expect(keySets.makeLocal(jwks)).type.toBe<
      Effect.Effect<JsonWebSignature.KeyResolver<JsonWebKeySet.SelectError>, JsonWebKeySet.MalformedKeySetError>
    >()
  })
})

describe("JsonWebKeySet.makeRemote", () => {
  it("requires only HttpClient with memory storage", () => {
    expect<Services<ReturnType<typeof keySets.makeRemote<{}>>>>().type.toBe<HttpClient.HttpClient>()
    const remote = keySets.makeRemote("https://issuer.example/jwks", { storage: "memory" })
    expect<Services<typeof remote>>().type.toBe<HttpClient.HttpClient>()
    expect<ResolverError<typeof remote>>().type.toBe<JsonWebKeySet.RemoteSelectError>()
    expect<ResolverServices<typeof remote>>().type.toBe<never>()
  })

  it("adds KeyValueStore and its error when keyValueStore storage is selected", () => {
    const remote = keySets.makeRemote("https://issuer.example/jwks", { storage: "keyValueStore" })
    expect<Services<typeof remote>>().type.toBe<HttpClient.HttpClient | KeyValueStore.KeyValueStore>()
    expect<ResolverError<typeof remote>>().type.toBe<
      JsonWebKeySet.RemoteSelectError | KeyValueStore.KeyValueStoreError
    >()
    expect<ResolverServices<typeof remote>>().type.toBe<never>()
  })
})
