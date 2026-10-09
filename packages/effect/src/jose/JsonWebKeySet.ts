/**
 * Selects verification keys from JSON Web Key Sets (RFC 7517 section 5).
 *
 * A key set is turned into a {@link JsonWebSignature.KeyResolver} that picks
 * the key matching a token's `alg` and `kid` headers. Remote key sets are
 * fetched with `HttpClient`, cached, and refreshed when an unknown `kid` is
 * seen, subject to a cooldown.
 *
 * @stability unstable
 * @since 4.0.0
 */
import * as Clock from "../Clock.ts"
import type * as Crypto from "../Crypto.ts"
import * as Duration from "../Duration.ts"
import * as Effect from "../Effect.ts"
import * as HttpClient from "../http/HttpClient.ts"
import type * as HttpClientError from "../http/HttpClientError.ts"
import * as Schema from "../Schema.ts"
import * as Semaphore from "../Semaphore.ts"
import { JWS } from "./internal/algorithms.ts"
import { isObject } from "./internal/shared.ts"
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
export type RemoteSelectError = SelectError | KeySetFetchError | KeySetTimeoutError

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
export type Resolver<E = SelectError> = JsonWebSignature.KeyResolver<E, Crypto.Crypto>

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
 * Creates a resolver that selects keys from an in-memory key set.
 *
 * **Details**
 *
 * A key is a candidate when its `kty` and `crv` suit the token's `alg`, its
 * `kid` matches when the token has one, and its `alg`, `use`, and `key_ops`
 * permit verification. Exactly one candidate must match. Imported keys are
 * cached per algorithm.
 *
 * **Gotchas**
 *
 * Key set members must be public keys, and symmetric `alg` values are
 * rejected.
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const makeLocal = (jwks: JwkSet): Effect.Effect<Resolver, MalformedKeySetError> =>
  Effect.suspend(() => {
    let snapshot: unknown
    try {
      snapshot = structuredClone(jwks)
    } catch {
      // reported below
    }
    if (!isJwkSet(snapshot)) return Effect.fail(new MalformedKeySetError({ message: "JSON Web Key Set malformed" }))
    const keys = snapshot.keys as ReadonlyArray<Record<string, unknown>>
    const cache = new Map<string, Crypto.Key>()
    const resolver: Resolver = (protectedHeader, token) =>
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
        if (candidates.length > 1) {
          return yield* Effect.fail(
            new MultipleMatchingKeysError({ message: "multiple matching keys found in the JSON Web Key Set" })
          )
        }
        const cacheKey = `${candidates[0]}:${entry.alg}`
        const cached = cache.get(cacheKey)
        if (cached) return cached
        const key = yield* JsonWebKey.jwkToKey(entry, keys[candidates[0]] as Crypto.JwkData, true)
        if (key.type !== "public") {
          return yield* Effect.fail(
            new MalformedKeySetError({ message: "JSON Web Key Set members must be public keys" })
          )
        }
        cache.set(cacheKey, key)
        return key
      })
    return Effect.succeed(resolver)
  })

/**
 * Options for remote key sets.
 *
 * **Details**
 *
 * - `cacheMaxAge`: how long a fetched set is considered fresh (10 minutes by
 *   default).
 * - `cooldownDuration`: minimum time between refetches triggered by an
 *   unknown key (30 seconds by default).
 * - `timeoutDuration`: request timeout (5 seconds by default).
 * - `headers`: additional request headers.
 *
 * @stability unstable
 * @category models
 * @since 4.0.0
 */
export interface RemoteOptions {
  readonly cacheMaxAge?: Duration.Input | undefined
  readonly cooldownDuration?: Duration.Input | undefined
  readonly timeoutDuration?: Duration.Input | undefined
  readonly headers?: Readonly<Record<string, string>> | undefined
}

/**
 * Creates a resolver backed by a key set fetched over HTTP.
 *
 * **Details**
 *
 * The set is fetched lazily on first use and refetched once it is older than
 * `cacheMaxAge`. When no key matches and the cooldown has elapsed, the set is
 * refetched and selection is retried once. Concurrent refetches are
 * coalesced.
 *
 * @stability unstable
 * @category constructors
 * @since 4.0.0
 */
export const makeRemote = (
  url: string | URL,
  options?: RemoteOptions
): Effect.Effect<Resolver<RemoteSelectError>, never, HttpClient.HttpClient> =>
  Effect.gen(function*() {
    const client = yield* HttpClient.HttpClient
    const cacheMaxAge = Duration.toMillis(options?.cacheMaxAge ?? Duration.minutes(10))
    const cooldown = Duration.toMillis(options?.cooldownDuration ?? Duration.seconds(30))
    const timeout = options?.timeoutDuration ?? Duration.seconds(5)
    const lock = yield* Semaphore.make(1)
    let local: Resolver | undefined
    let fetchedAt = -Infinity

    const href = url.toString()
    const fetchSet: Effect.Effect<unknown, KeySetFetchError | KeySetTimeoutError> = client.get(url, {
      headers: { accept: "application/json", ...options?.headers }
    }).pipe(
      Effect.flatMap((response): Effect.Effect<unknown, KeySetFetchError | HttpClientError.HttpClientError> =>
        response.status === 200
          ? response.json
          : Effect.fail(
            new KeySetFetchError({
              url: href,
              message: `Expected 200 OK from the JSON Web Key Set HTTP response, received ${response.status}`
            })
          )
      ),
      Effect.mapError((e) =>
        e._tag === "KeySetFetchError"
          ? e
          : new KeySetFetchError({ url: href, message: "Failed to fetch the JSON Web Key Set", cause: e })
      ),
      Effect.timeoutOrElse({
        duration: timeout,
        orElse: () => Effect.fail(new KeySetTimeoutError({ url: href, message: "request timed out" }))
      })
    )

    const reload = (
      force: boolean
    ): Effect.Effect<Resolver, MalformedKeySetError | KeySetFetchError | KeySetTimeoutError> =>
      lock.withPermit(Effect.gen(function*() {
        const now = yield* Clock.currentTimeMillis
        if (!force && local !== undefined && now - fetchedAt < cacheMaxAge) return local
        const json = yield* fetchSet
        local = yield* makeLocal(json as unknown as JwkSet)
        fetchedAt = yield* Clock.currentTimeMillis
        return local
      }))

    const resolver: Resolver<RemoteSelectError> = (protectedHeader, token) =>
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
    return resolver
  })
