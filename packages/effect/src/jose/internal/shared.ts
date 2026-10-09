import type * as Crypto from "../../Crypto.ts"
import * as Effect from "../../Effect.ts"
import * as Base64Url from "../../encoding/Base64Url.ts"
import type * as PlatformError from "../../PlatformError.ts"
import * as Redacted from "../../Redacted.ts"
import * as Result from "../../Result.ts"

/** @internal */
export const encoder = new TextEncoder()

/** @internal */
export const strictDecoder = new TextDecoder("utf-8", { fatal: true })

/**
 * Builds an error from a message. Shared helpers take one of these so each
 * module raises its own error type.
 *
 * @internal
 */
export type MakeError<E> = (message: string) => E

/**
 * Throws a tagged error from synchronous validation code; {@link attempt}
 * moves it to the failure channel.
 *
 * @internal
 */
export const raise = (error: unknown): never => {
  throw error
}

/**
 * Runs synchronous validation that throws tagged errors, capturing them in
 * the failure channel with type `E`. Anything else thrown is a defect.
 *
 * @internal
 */
export const attemptWith = <E>() => <A>(f: () => A): Effect.Effect<A, E> =>
  Effect.suspend(() => {
    try {
      return Effect.succeed(f())
    } catch (e) {
      return typeof e === "object" && e !== null && typeof (e as { _tag?: unknown })._tag === "string"
        ? Effect.fail(e as E)
        : Effect.die(e)
    }
  })

/**
 * Maps a platform failure to a more specific error, leaving other platform
 * failures as `PlatformError`.
 *
 * @internal
 */
export const mapPlatformError = <A, E, R, E2>(
  effect: Effect.Effect<A, E | PlatformError.PlatformError, R>,
  f: (error: PlatformError.PlatformError) => E2
): Effect.Effect<A, Exclude<E, PlatformError.PlatformError> | E2, R> =>
  Effect.mapError(effect, (e: any) => (e?._tag === "PlatformError" ? f(e) : e)) as any

/** @internal */
export const concat = (...buffers: ReadonlyArray<Uint8Array>): Uint8Array => {
  let size = 0
  for (const buffer of buffers) size += buffer.length
  const out = new Uint8Array(size)
  let offset = 0
  for (const buffer of buffers) {
    out.set(buffer, offset)
    offset += buffer.length
  }
  return out
}

/** @internal */
export const uint32be = (value: number): Uint8Array => {
  const out = new Uint8Array(4)
  out[0] = value >>> 24
  out[1] = value >>> 16
  out[2] = value >>> 8
  out[3] = value & 0xff
  return out
}

/** @internal */
export const uint64be = (value: number): Uint8Array =>
  concat(uint32be(Math.floor(value / 2 ** 32)), uint32be(value % 2 ** 32))

/**
 * Encodes ASCII text as bytes, returning `undefined` for non-ASCII input.
 *
 * @internal
 */
export const ascii = (input: string): Uint8Array | undefined => {
  const out = new Uint8Array(input.length)
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i)
    if (code > 127) return undefined
    out[i] = code
  }
  return out
}

/**
 * Encodes bytes or UTF-8 text as unpadded base64url.
 *
 * @internal
 */
export const b64u = (input: Uint8Array | string): string => Base64Url.encode(input)

const UNPADDED_BASE64URL = /^[A-Za-z0-9_-]*$/

/**
 * Decodes base64url as JOSE requires (RFC 7515 section 2): no padding,
 * whitespace, or characters outside the base64url alphabet. Returns
 * `undefined` for invalid input.
 *
 * @internal
 */
export const b64uDecode = (input: string): Uint8Array | undefined => {
  if (input.length % 4 === 1 || !UNPADDED_BASE64URL.test(input)) return undefined
  const decoded = Base64Url.decode(input)
  return Result.isSuccess(decoded) ? decoded.success : undefined
}

/** @internal */
export const decodeB64u = <E>(
  value: string,
  label: string,
  make: MakeError<E>
): Uint8Array => b64uDecode(value) ?? raise(make(`Failed to base64url decode the ${label}`))

/** @internal */
export const isObject = (input: unknown): input is Record<string, unknown> => {
  if (typeof input !== "object" || input === null || Object.prototype.toString.call(input) !== "[object Object]") {
    return false
  }
  const prototype = Object.getPrototypeOf(input)
  return prototype === null || Object.getPrototypeOf(prototype) === null
}

/** @internal */
export const isDisjoint = (...headers: ReadonlyArray<object | undefined>): boolean => {
  const seen = new Set<string>()
  for (const header of headers) {
    if (header === undefined) continue
    for (const name of Object.keys(header)) {
      if (seen.has(name)) return false
      seen.add(name)
    }
  }
  return true
}

/** @internal */
export const parseHeader = <E>(
  encoded: string,
  make: MakeError<E>,
  message: string
): Record<string, unknown> => {
  let parsed: unknown
  try {
    const bytes = b64uDecode(encoded)
    if (bytes === undefined) return raise(make(message))
    parsed = JSON.parse(strictDecoder.decode(bytes))
  } catch {
    return raise(make(message))
  }
  if (!isObject(parsed)) return raise(make(message))
  return parsed
}

/** @internal */
export const serializeHeader = <E>(make: MakeError<E>, header: unknown): [Record<string, unknown>, string] => {
  let serialized: string
  let parsed: unknown
  try {
    serialized = JSON.stringify(header)
    parsed = JSON.parse(serialized)
  } catch {
    return raise(make("JOSE Header is not valid JSON"))
  }
  if (!isObject(parsed)) return raise(make("JOSE Header is not a JSON object"))
  return [parsed, serialized]
}

/** @internal */
export const JWS_RECOGNIZED: Readonly<Record<string, boolean>> = { __proto__: null, b64: true } as any

/** @internal */
export const JWE_RECOGNIZED: Readonly<Record<string, boolean>> = { __proto__: null } as any

/**
 * Validates the `crit` header parameter, returning the list of critical
 * extension parameters.
 *
 * `recognizedOption` maps extension names the caller understands to whether
 * they must be integrity protected.
 *
 * @internal
 */
export const validateCrit = <E1, E2>(
  malformed: MakeError<E1>,
  unsupported: MakeError<E2>,
  recognizedDefault: Readonly<Record<string, boolean>>,
  recognizedOption: Readonly<Record<string, boolean>> | undefined,
  protectedHeader: Record<string, unknown> | undefined,
  joseHeader: Record<string, unknown>
): ReadonlyArray<string> => {
  if (joseHeader.crit !== undefined && protectedHeader?.crit === undefined) {
    return raise(malformed("\"crit\" (Critical) Header Parameter MUST be integrity protected"))
  }
  if (protectedHeader === undefined || protectedHeader.crit === undefined) return []
  const crit = protectedHeader.crit
  if (
    !Array.isArray(crit) || crit.length === 0 ||
    crit.some((input) => typeof input !== "string" || input.length === 0)
  ) {
    return raise(malformed("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present"))
  }
  if (new Set(crit).size !== crit.length) {
    return raise(malformed("\"crit\" (Critical) Header Parameter MUST NOT contain duplicate values"))
  }
  const recognized: Record<string, boolean> = recognizedOption === undefined
    ? recognizedDefault
    : { __proto__: null, ...recognizedOption, ...recognizedDefault } as any
  for (const parameter of crit as Array<string>) {
    if (!(parameter in recognized)) {
      return raise(unsupported(`Extension Header Parameter "${parameter}" is not recognized`))
    }
    if (!Object.hasOwn(joseHeader, parameter) || joseHeader[parameter] === undefined) {
      return raise(malformed(`Extension Header Parameter "${parameter}" is missing`))
    }
    if (
      recognized[parameter] && (!Object.hasOwn(protectedHeader, parameter) || protectedHeader[parameter] === undefined)
    ) {
      return raise(malformed(`Extension Header Parameter "${parameter}" MUST be integrity protected`))
    }
  }
  return crit as Array<string>
}

/** @internal */
export const validateB64 = <E>(
  malformed: MakeError<E>,
  protectedHeader: Record<string, unknown>,
  extensions: ReadonlyArray<string>
): boolean => {
  if (extensions.includes("b64")) {
    const b64 = protectedHeader.b64
    if (typeof b64 !== "boolean") {
      return raise(malformed("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean"))
    }
    return b64
  }
  return true
}

/** @internal */
export const validateAlgorithms = (
  option: string,
  algorithms: ReadonlyArray<string> | undefined
): ReadonlySet<string> | undefined => {
  if (algorithms === undefined) return undefined
  if (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string")) {
    throw new TypeError(`"${option}" option must be an array of strings`)
  }
  return new Set(algorithms)
}

/**
 * Compares two byte arrays in time independent of where they differ.
 *
 * @internal
 */
export const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  let diff = a.length ^ b.length
  const length = Math.max(a.length, b.length)
  for (let i = 0; i < length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  }
  return diff === 0
}

/** @internal */
export const isCryptoKey = (u: unknown): u is Crypto.Key =>
  typeof u === "object" && u !== null && !(u instanceof Uint8Array) &&
  "usages" in u && "algorithm" in u && "type" in u && "extractable" in u && !isObject(u)

/**
 * Default upper bound on the length of a compact token, in characters.
 *
 * @internal
 */
export const DEFAULT_MAX_TOKEN_LENGTH = 65_536

/**
 * Reads a token given as a string, bytes, or a `Redacted` string. Returns
 * `undefined` for anything else.
 *
 * @internal
 */
export const readToken = (input: unknown): string | undefined => {
  const value = Redacted.isRedacted(input) ? Redacted.value(input) : input
  if (value instanceof Uint8Array) return new TextDecoder().decode(value)
  return typeof value === "string" ? value : undefined
}

/**
 * Validates a maximum length option, returning the default when omitted.
 *
 * @internal
 */
export const maxTokenLength = (value: number | undefined): number => {
  if (value === undefined) return DEFAULT_MAX_TOKEN_LENGTH
  if (value !== Infinity && (!Number.isSafeInteger(value) || value < 1)) {
    throw new TypeError("maxTokenLength must be a positive safe integer or Infinity")
  }
  return value
}
