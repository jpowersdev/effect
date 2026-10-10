/**
 * Selects verification keys from JSON Web Key Sets (RFC 7517 section 5).
 *
 * The {@link JsonWebKeySet} service turns a key set into a
 * {@link JsonWebSignature.KeyResolver} that picks the key matching a token's
 * `alg` and `kid` headers. Remote key sets are
 * fetched with `HttpClient`, cached, and refreshed when an unknown `kid` is
 * seen, subject to a cooldown.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Clock from "../Clock.ts"
import * as Context from "../Context.ts"
import * as Crypto from "../Crypto.ts"
import * as Duration from "../Duration.ts"
import * as Effect from "../Effect.ts"
import * as FetchHttpClient from "../http/FetchHttpClient.ts"
import * as HttpClient from "../http/HttpClient.ts"
import type * as HttpClientError from "../http/HttpClientError.ts"
import * as Layer from "../Layer.ts"
import * as KeyValueStore from "../persistence/KeyValueStore.ts"
import * as Schema from "../Schema.ts"
import * as Semaphore from "../Semaphore.ts"
import * as Stream from "../Stream.ts"
import { JWS } from "./internal/algorithms.ts"
import { isObject, provideCrypto } from "./internal/shared.ts"
import { UnsupportedAlgorithmError } from "./JsonWebAlgorithm.ts"
import * as JsonWebKey from "./JsonWebKey.ts"
import type * as JsonWebSignature from "./JsonWebSignature.ts"

/**
 * Error raised when a key set is malformed: it is not an object with a
 * `keys` array of objects, or a selected member is not a public key.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class MalformedKeySetError
  extends Schema.TaggedError<MalformedKeySetError>("effect/jose/JsonWebKeySet/MalformedKeySetError")(
    "MalformedKeySetError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when no key in the set matches the token's `alg` and `kid`.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class NoMatchingKeyError
  extends Schema.TaggedError<NoMatchingKeyError>("effect/jose/JsonWebKeySet/NoMatchingKeyError")(
    "NoMatchingKeyError",
    { message: Schema.String, kid: Schema.optional(Schema.String) }
  )
{}

/**
 * Error raised when more than one key in the set matches the token, usually
 * because the token has no `kid`.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class MultipleMatchingKeysError
  extends Schema.TaggedError<MultipleMatchingKeysError>("effect/jose/JsonWebKeySet/MultipleMatchingKeysError")(
    "MultipleMatchingKeysError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when a remote key set cannot be fetched or does not respond
 * with `200 OK`.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class KeySetFetchError
  extends Schema.TaggedError<KeySetFetchError>("effect/jose/JsonWebKeySet/KeySetFetchError")(
    "KeySetFetchError",
    { message: Schema.String, url: Schema.String, cause: Schema.optional(Schema.Defect()) }
  )
{}

/**
 * Error raised when fetching a remote key set exceeds `timeoutDuration`.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class KeySetTimeoutError
  extends Schema.TaggedError<KeySetTimeoutError>("effect/jose/JsonWebKeySet/KeySetTimeoutError")(
    "KeySetTimeoutError",
    { message: Schema.String, url: Schema.String }
  )
{}

/**
 * Error raised when a remote key set URL is not acceptable: it is not
 * `https:` (unless `allowInsecureHttp` is set), or it contains credentials or
 * a fragment.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class InvalidKeySetUrlError
  extends Schema.TaggedError<InvalidKeySetUrlError>("effect/jose/JsonWebKeySet/InvalidKeySetUrlError")(
    "InvalidKeySetUrlError",
    { message: Schema.String }
  )
{}

/**
 * Error raised when a remote key set response exceeds `maxResponseBytes`, or
 * the set has more than `maxKeys` keys.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export class KeySetTooLargeError
  extends Schema.TaggedError<KeySetTooLargeError>("effect/jose/JsonWebKeySet/KeySetTooLargeError")(
    "KeySetTooLargeError",
    { message: Schema.String, url: Schema.String }
  )
{}

/**
 * Failures from selecting a key from a key set.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type SelectError =
  | MalformedKeySetError
  | NoMatchingKeyError
  | MultipleMatchingKeysError
  | UnsupportedAlgorithmError
  | JsonWebKey.KeyError

/**
 * Failures from selecting a key from a remote key set.
 *
 * @stability unstable
 * @category errors
 * @since 4.0.0
 */
export type RemoteSelectError = SelectError | KeySetFetchError | KeySetTimeoutError | KeySetTooLargeError

/**
 * A JSON Web Key Set.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface JwkSet {
  readonly keys: ReadonlyArray<Crypto.JwkData>
}

/**
 * Schema for JSON Web Key Sets.
 *
 * @stability unstable
 * @category schemas
 * @since 4.0.0
 */
export const JwkSet = Schema.Struct({ keys: Schema.Array(JsonWebKey.Jwk) })

/**
 * Resolves a verification key for a token from a key set.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Resolver<E = SelectError> = JsonWebSignature.KeyResolver<E>

/** A resolver before the service binds it to its `Crypto` service. */
type CryptoResolver<E = SelectError> = JsonWebSignature.KeyResolver<E, Crypto.Crypto>

const isJwkSet = (input: unknown): input is JwkSet =>
  isObject(input) && Array.isArray(input.keys) && input.keys.every(isObject)

const isUsable = (jwk: Record<string, unknown>, entry: (typeof JWS)[string], alg: string, kid: unknown): boolean => {
  const { kty, key_ops: keyOps, ext, kid: jwkKid, alg: jwkAlg, use, crv } = jwk
  return (ext === undefined || typeof ext === "boolean") &&
    (keyOps === undefined ||
      (Array.isArray(keyOps) &&
        keyOps.every((op, index) => typeof op === "string" && keyOps.indexOf(op) === index) &&
        keyOps.includes("verify"))) &&
    entry.kty.includes(kty as string) &&
    (kid === undefined || (typeof kid === "string" && kid === jwkKid)) &&
    (jwkAlg === undefined || alg === jwkAlg) &&
    (use === undefined || use === "sig") &&
    (!entry.crv || crv === entry.crv)
}

/**
 * Options for selecting keys from a key set.
 *
 * **Details**
 *
 * `multipleMatches` controls what happens when several keys match a token,
 * usually because it has no `kid`. `"fail"` (the default) fails with
 * {@link MultipleMatchingKeysError}; `"tryEach"` passes every matching key to
 * verification, which succeeds with the first one whose signature verifies.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface LocalOptions {
  readonly multipleMatches?: "fail" | "tryEach" | undefined
}

const makeLocal = (jwks: JwkSet, options?: LocalOptions): Effect.Effect<CryptoResolver, MalformedKeySetError> =>
  Effect.suspend(() => {
    let snapshot: unknown
    try {
      snapshot = structuredClone(jwks)
    } catch {
      // reported below
    }
    if (!isJwkSet(snapshot)) return Effect.fail(new MalformedKeySetError({ message: "JSON Web Key Set malformed" }))
    const keys = snapshot.keys as ReadonlyArray<Record<string, unknown>>
    const tryEach = options?.multipleMatches === "tryEach"
    const cache = new Map<string, Crypto.Key>()
    const importKey = (index: number, entry: (typeof JWS)[string]) =>
      Effect.gen(function*() {
        const cacheKey = `${index}:${entry.alg}`
        const cached = cache.get(cacheKey)
        if (cached) return cached
        const key = yield* JsonWebKey.jwkToKey(entry, keys[index] as Crypto.JwkData, true)
        if (key.type !== "public") {
          return yield* Effect.fail(
            new MalformedKeySetError({ message: "JSON Web Key Set members must be public keys" })
          )
        }
        cache.set(cacheKey, key)
        return key
      })
    const resolver: CryptoResolver = (protectedHeader, token) =>
      Effect.gen(function*() {
        const { alg, kid } = { ...protectedHeader, ...token?.header }
        const entry = typeof alg === "string" ? JWS[alg] : undefined
        if (!entry || entry.secret) {
          return yield* Effect.fail(
            new UnsupportedAlgorithmError({
              ...(typeof alg === "string" ? { algorithm: alg } : {}),
              message: "Unsupported \"alg\" value for a JSON Web Key Set"
            })
          )
        }
        const candidates: Array<number> = []
        keys.forEach((jwk, index) => {
          if (isUsable(jwk, entry, alg as string, kid)) candidates.push(index)
        })
        if (candidates.length === 0) {
          return yield* Effect.fail(
            new NoMatchingKeyError({
              ...(typeof kid === "string" ? { kid } : {}),
              message: "no applicable key found in the JSON Web Key Set"
            })
          )
        }
        if (candidates.length === 1) return yield* importKey(candidates[0], entry)
        if (!tryEach) {
          return yield* Effect.fail(
            new MultipleMatchingKeysError({ message: "multiple matching keys found in the JSON Web Key Set" })
          )
        }
        const imported: Array<Crypto.Key> = []
        for (const index of candidates) imported.push(yield* importKey(index, entry))
        return imported as unknown as JsonWebSignature.KeyCandidates
      })
    return Effect.succeed(resolver)
  })

/**
 * Where a remote key set keeps the last fetched keys.
 *
 * **Details**
 *
 * - `"memory"` (the default): in this process only.
 * - `"keyValueStore"`: also in the `KeyValueStore` service, so a restarted
 *   process (for example a serverless cold start) reuses the last fetch until
 *   it is older than `cacheMaxAge`. Selecting it adds `KeyValueStore` to the
 *   requirements and `KeyValueStoreError` to the resolver's errors.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type Storage = "memory" | "keyValueStore"

/**
 * Options for remote key sets.
 *
 * **Details**
 *
 * - `cacheMaxAge`: the longest a fetched set is considered fresh (10 minutes by
 *   default). A shorter `Cache-Control: max-age` on the response takes
 *   precedence.
 * - `cooldownDuration`: minimum time between refetches triggered by an
 *   unknown key (30 seconds by default).
 * - `timeoutDuration`: request timeout (5 seconds by default).
 * - `headers`: additional request headers.
 * - `allowInsecureHttp`: permit `http:` URLs, for local development and
 *   tests. Off by default.
 * - `maxResponseBytes`: largest accepted response body (128 KiB by default).
 * - `maxKeys`: most keys accepted in the set (64 by default).
 * - `storage`: see {@link Storage}.
 * - `storageKey`: the `KeyValueStore` key (derived from the URL by default).
 *
 * To customize how the set is fetched (fetch implementation, retries,
 * tracing), provide a customized `HttpClient`. Redirects are refused: the
 * request asks `fetch` to fail on redirects, and any response from a
 * different URL is rejected, whichever client is used.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface RemoteOptions extends LocalOptions {
  readonly allowInsecureHttp?: boolean | undefined
  readonly maxResponseBytes?: number | undefined
  readonly maxKeys?: number | undefined
  readonly cacheMaxAge?: Duration.Input | undefined
  readonly cooldownDuration?: Duration.Input | undefined
  readonly timeoutDuration?: Duration.Input | undefined
  readonly headers?: Readonly<Record<string, string>> | undefined
  readonly storage?: Storage | undefined
  readonly storageKey?: string | undefined
}

/**
 * The services a remote key set requires for the selected storage.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type StorageServices<O> = O extends { readonly storage: "keyValueStore" } ? KeyValueStore.KeyValueStore
  : never

/**
 * The additional failures of a remote key set for the selected storage.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export type StorageError<O> = O extends { readonly storage: "keyValueStore" } ? KeyValueStore.KeyValueStoreError
  : never

const StoredKeySet = Schema.fromJsonString(
  Schema.Struct({ fetchedAt: Schema.Finite, expiresAt: Schema.Finite, jwks: JwkSet })
)

/**
 * A resolver backed by a remote key set, with an explicit `refresh`.
 *
 * **Details**
 *
 * `refresh` fetches the key set now, bypassing the cache. Run it once at
 * startup so the first request does not wait for the fetch, or repeat it on a
 * schedule to refresh in the background.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface RemoteResolver<E> extends Resolver<E> {
  readonly refresh: Effect.Effect<void, Exclude<E, SelectError> | MalformedKeySetError>
}

interface CryptoRemoteResolver<E> extends CryptoResolver<E> {
  readonly refresh: Effect.Effect<void, Exclude<E, SelectError> | MalformedKeySetError>
}

const cacheControlMaxAge = (header: string | undefined): number | undefined => {
  if (header === undefined) return undefined
  const match = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?\s*(?:,|$)/i.exec(header)
  return match === null ? undefined : Number(match[1])
}

const validateUrl = (url: string | URL, allowInsecureHttp: boolean): Effect.Effect<URL, InvalidKeySetUrlError> => {
  let parsed: URL
  try {
    parsed = new URL(url.toString())
  } catch {
    return Effect.fail(new InvalidKeySetUrlError({ message: "JSON Web Key Set URL is not a valid URL" }))
  }
  if (parsed.protocol !== "https:" && !(allowInsecureHttp && parsed.protocol === "http:")) {
    return Effect.fail(
      new InvalidKeySetUrlError({ message: "JSON Web Key Set URL must use https: (or set allowInsecureHttp)" })
    )
  }
  if (parsed.username !== "" || parsed.password !== "") {
    return Effect.fail(new InvalidKeySetUrlError({ message: "JSON Web Key Set URL must not contain credentials" }))
  }
  if (parsed.hash !== "") {
    return Effect.fail(new InvalidKeySetUrlError({ message: "JSON Web Key Set URL must not contain a fragment" }))
  }
  return Effect.succeed(parsed)
}

const concatChunks = (chunks: ReadonlyArray<Uint8Array>): Uint8Array => {
  const out = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0))
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

const makeRemote = <const O extends RemoteOptions = {}>(
  url: string | URL,
  options?: O
): Effect.Effect<
  CryptoRemoteResolver<RemoteSelectError | StorageError<O>>,
  InvalidKeySetUrlError,
  HttpClient.HttpClient | StorageServices<O>
> =>
  Effect.gen(function*() {
    const parsed = yield* validateUrl(url, options?.allowInsecureHttp === true)
    const client = yield* HttpClient.HttpClient
    const store = options?.storage === "keyValueStore"
      ? yield* Effect.service(KeyValueStore.KeyValueStore)
      : undefined
    const href = parsed.href
    const maxResponseBytes = options?.maxResponseBytes ?? 131_072
    const maxKeys = options?.maxKeys ?? 64
    const storageKey = options?.storageKey ?? `effect/jose/JsonWebKeySet/${href}`
    const cacheMaxAge = Duration.toMillis(options?.cacheMaxAge ?? Duration.minutes(10))
    const cooldown = Duration.toMillis(options?.cooldownDuration ?? Duration.seconds(30))
    const timeout = options?.timeoutDuration ?? Duration.seconds(5)
    const localOptions: LocalOptions = { multipleMatches: options?.multipleMatches }
    const lock = yield* Semaphore.make(1)
    let local: CryptoResolver | undefined
    let fetchedAt = -Infinity
    let expiresAt = -Infinity

    const tooLarge = (message: string) => new KeySetTooLargeError({ url: href, message })

    const readBody = (stream: Stream.Stream<Uint8Array, HttpClientError.HttpClientError>) =>
      Stream.runFoldEffect(
        stream,
        () => [] as Array<Uint8Array>,
        (chunks, chunk): Effect.Effect<Array<Uint8Array>, KeySetTooLargeError> => {
          const size = chunks.reduce((total, c) => total + c.length, 0) + chunk.length
          if (size > maxResponseBytes) {
            return Effect.fail(tooLarge(`JSON Web Key Set response exceeds ${maxResponseBytes} bytes`))
          }
          chunks.push(chunk)
          return Effect.succeed(chunks)
        }
      )

    const fetchSet: Effect.Effect<
      { readonly json: unknown; readonly maxAge: number | undefined },
      KeySetFetchError | KeySetTimeoutError | KeySetTooLargeError
    > = client.get(href, {
      headers: { accept: "application/json", ...options?.headers }
    }).pipe(
      Effect.flatMap((response) => {
        if (response.status !== 200) {
          return Effect.fail(
            new KeySetFetchError({
              url: href,
              message: `Expected 200 OK from the JSON Web Key Set HTTP response, received ${response.status}`
            })
          )
        }
        if (response.url !== href) {
          return Effect.fail(
            new KeySetFetchError({ url: href, message: `Refusing a response from a different URL: ${response.url}` })
          )
        }
        const maxAge = cacheControlMaxAge(response.headers["cache-control"])
        return Effect.flatMap(readBody(response.stream), (chunks) => {
          const body = new TextDecoder().decode(concatChunks(chunks))
          return Effect.try({
            try: () => ({ json: JSON.parse(body) as unknown, maxAge }),
            catch: (cause) => new KeySetFetchError({ url: href, message: "Response is not JSON", cause })
          })
        })
      }),
      Effect.flatMap((fetched) =>
        isObject(fetched.json) && Array.isArray(fetched.json.keys) && fetched.json.keys.length > maxKeys
          ? Effect.fail(tooLarge(`JSON Web Key Set has more than ${maxKeys} keys`))
          : Effect.succeed(fetched)
      ),
      Effect.mapError((e) =>
        e._tag === "KeySetFetchError" || e._tag === "KeySetTooLargeError"
          ? e
          : new KeySetFetchError({ url: href, message: "Failed to fetch the JSON Web Key Set", cause: e })
      ),
      Effect.provideService(FetchHttpClient.RequestInit, { redirect: "error" }),
      Effect.timeoutOrElse({
        duration: timeout,
        orElse: () => Effect.fail(new KeySetTimeoutError({ url: href, message: "request timed out" }))
      })
    )

    const loadStored = (now: number) =>
      Effect.gen(function*() {
        if (store === undefined) return false
        const raw = yield* store.get(storageKey)
        if (raw === undefined) return false
        const stored = yield* Effect.option(Schema.decodeUnknownEffect(StoredKeySet)(raw))
        if (stored._tag === "None" || now >= stored.value.expiresAt) return false
        const resolver = yield* Effect.option(makeLocal(stored.value.jwks as JwkSet, localOptions))
        if (resolver._tag === "None") return false
        local = resolver.value
        fetchedAt = stored.value.fetchedAt
        expiresAt = stored.value.expiresAt
        return true
      })

    const reload = (force: boolean) =>
      lock.withPermit(Effect.gen(function*() {
        const now = yield* Clock.currentTimeMillis
        if (!force && local !== undefined && now < expiresAt) return local
        if (!force && local === undefined && (yield* loadStored(now))) return local!
        const { json, maxAge } = yield* fetchSet
        local = yield* makeLocal(json as JwkSet, localOptions)
        fetchedAt = yield* Clock.currentTimeMillis
        // The response's Cache-Control max-age shortens freshness; cacheMaxAge caps it.
        expiresAt = fetchedAt + (maxAge === undefined ? cacheMaxAge : Math.min(maxAge * 1000, cacheMaxAge))
        if (store !== undefined) yield* store.set(storageKey, JSON.stringify({ fetchedAt, expiresAt, jwks: json }))
        return local
      }))

    const resolver: CryptoResolver<RemoteSelectError | KeyValueStore.KeyValueStoreError> = (protectedHeader, token) =>
      Effect.gen(function*() {
        const resolve = yield* reload(false)
        const result = yield* Effect.result(resolve(protectedHeader, token))
        if (result._tag === "Success") return result.success
        if (result.failure._tag !== "NoMatchingKeyError") return yield* Effect.fail(result.failure)
        const now = yield* Clock.currentTimeMillis
        if (now - fetchedAt < cooldown) return yield* Effect.fail(result.failure)
        const fresh = yield* reload(true)
        return yield* fresh(protectedHeader, token)
      })
    return Object.assign(resolver, { refresh: Effect.asVoid(reload(true)) }) as CryptoRemoteResolver<
      RemoteSelectError | StorageError<O>
    >
  }) as unknown as Effect.Effect<
    CryptoRemoteResolver<RemoteSelectError | StorageError<O>>,
    InvalidKeySetUrlError,
    HttpClient.HttpClient | StorageServices<O>
  >

/**
 * Creates key resolvers from JSON Web Key Sets, importing their keys with the
 * `Crypto` service provided to {@link layer}.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface JsonWebKeySet {
  /**
   * Creates a resolver that selects keys from an in-memory key set.
   *
   * **Details**
   *
   * A key is a candidate when its `kty` and `crv` suit the token's `alg`, its
   * `kid` matches when the token has one, and its `alg`, `use`, and `key_ops`
   * permit verification. Exactly one candidate must match unless
   * `multipleMatches` is `"tryEach"`. Imported keys are cached per algorithm.
   *
   * **Gotchas**
   *
   * Key set members must be public keys, and symmetric `alg` values are
   * rejected.
   */
  readonly makeLocal: (jwks: JwkSet, options?: LocalOptions) => Effect.Effect<Resolver, MalformedKeySetError>

  /**
   * Creates a resolver backed by a key set fetched over HTTP.
   *
   * **Details**
   *
   * The set is fetched lazily on first use and refetched once it is older than
   * `cacheMaxAge`. When no key matches and the cooldown has elapsed, the set is
   * refetched and selection is retried once. Concurrent refetches are
   * coalesced. With `"keyValueStore"` storage, a stored set is used on first use
   * when it is still fresh, and every fetch is written back; a stored value
   * that cannot be decoded is treated as missing.
   */
  readonly makeRemote: <const O extends RemoteOptions = {}>(
    url: string | URL,
    options?: O
  ) => Effect.Effect<
    RemoteResolver<RemoteSelectError | StorageError<O>>,
    InvalidKeySetUrlError,
    HttpClient.HttpClient | StorageServices<O>
  >
}

/**
 * The {@link JsonWebKeySet} service.
 *
 * @stability unstable
 * @category services
 * @since 4.0.0
 */
export const JsonWebKeySet: Context.Service<
  JsonWebKeySet,
  JsonWebKeySet
> = Context.Service("effect/jose/JsonWebKeySet")

/**
 * Creates the {@link JsonWebKeySet} service with the current `Crypto` service.
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const make: Effect.Effect<JsonWebKeySet, never, Crypto.Crypto> = Effect.map(
  Effect.service(Crypto.Crypto),
  (crypto) => {
    const provide = provideCrypto(crypto)
    return JsonWebKeySet.of({
      makeLocal: (jwks, options) => Effect.map(makeLocal(jwks, options), provide),
      makeRemote: (url, options) =>
        Effect.map(makeRemote(url, options), (remote) => Object.assign(provide(remote), { refresh: remote.refresh }))
    })
  }
)

/**
 * Provides the {@link JsonWebKeySet} service, requiring `Crypto`.
 *
 * **Example** (Verifying tokens against an identity provider's key set)
 *
 * ```ts
 * import { Effect } from "effect"
 * import { JsonWebKeySet, JsonWebToken } from "effect/jose"
 *
 * declare const token: string
 *
 * const program = Effect.gen(function*() {
 *   const keySets = yield* JsonWebKeySet.JsonWebKeySet
 *   const jwt = yield* JsonWebToken.JsonWebToken
 *   const keySet = yield* keySets.makeRemote("https://auth.example.com/.well-known/jwks.json")
 *   const { payload } = yield* jwt.verify(token, keySet, {
 *     algorithms: ["ES256"],
 *     issuer: "https://auth.example.com"
 *   })
 *   return payload.sub
 * })
 * ```
 *
 * @stability unstable
 * @category layers
 * @since 4.0.0
 */
export const layer: Layer.Layer<JsonWebKeySet, never, Crypto.Crypto> = Layer.effect(JsonWebKeySet, make)
