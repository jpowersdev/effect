import type * as Crypto from "../Crypto.ts"
import * as Effect from "../Effect.ts"
import * as PlatformError from "../PlatformError.ts"

const fail = (method: string, description: string, cause?: unknown) =>
  PlatformError.systemError({
    module: "Crypto",
    method,
    _tag: "Unknown",
    description,
    cause
  })

const unsupported = (method: string) => () =>
  Effect.fail(fail(method, `${method} is not supported by this Crypto implementation`))

/** @internal */
export const unsupportedKeyOperations: Crypto.KeyOperations = {
  importKey: unsupported("importKey"),
  exportKey: unsupported("exportKey"),
  generateKey: unsupported("generateKey"),
  sign: unsupported("sign"),
  verify: unsupported("verify"),
  encrypt: unsupported("encrypt"),
  decrypt: unsupported("decrypt"),
  deriveBits: unsupported("deriveBits"),
  wrapKey: unsupported("wrapKey"),
  unwrapKey: unsupported("unwrapKey")
}

const bytes = (data: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(data)

class KeyImpl implements Crypto.Key {
  readonly type: Crypto.Key["type"]
  readonly algorithm: Crypto.KeyAlgorithmInfo
  readonly extractable: boolean
  readonly usages: ReadonlyArray<Crypto.KeyUsage>
  constructor(native: any) {
    this.type = native.type
    this.extractable = native.extractable
    this.usages = Array.from(native.usages)
    const algorithm = native.algorithm
    this.algorithm = {
      name: algorithm.name,
      ...(algorithm.hash !== undefined
        ? { hash: typeof algorithm.hash === "string" ? algorithm.hash : algorithm.hash.name }
        : {}),
      ...(algorithm.namedCurve !== undefined ? { namedCurve: algorithm.namedCurve } : {}),
      ...(algorithm.length !== undefined ? { length: algorithm.length } : {}),
      ...(algorithm.modulusLength !== undefined ? { modulusLength: algorithm.modulusLength } : {})
    }
  }
  toJSON() {
    return { _id: "Crypto.Key", type: this.type, algorithm: this.algorithm, usages: this.usages }
  }
}

/** @internal */
export const makeKeyOperations = (subtle: Crypto.SubtleCryptoLike): Crypto.KeyOperations => {
  const natives = new WeakMap<Crypto.Key, unknown>()

  const wrap = (native: any): Crypto.Key => {
    const key = new KeyImpl(native)
    natives.set(key, native)
    return key
  }

  const unwrap = (method: string, key: Crypto.Key): Effect.Effect<any, PlatformError.PlatformError> => {
    const native = natives.get(key)
    return native === undefined
      ? Effect.fail(PlatformError.badArgument({
        module: "Crypto",
        method,
        description: "key was not created by this Crypto implementation"
      }))
      : Effect.succeed(native)
  }

  const run = <A>(method: string, description: string, f: () => Promise<A>) =>
    Effect.tryPromise({
      try: f,
      catch: (cause) => fail(method, description, cause)
    })

  const keyAlgorithm = (algorithm: Crypto.KeyAlgorithm): any => {
    switch (algorithm.name) {
      case "RSASSA-PKCS1-v1_5":
      case "RSA-PSS":
      case "RSA-OAEP":
        return {
          name: algorithm.name,
          hash: algorithm.hash,
          modulusLength: algorithm.modulusLength ?? 2048,
          publicExponent: algorithm.publicExponent ? bytes(algorithm.publicExponent) : new Uint8Array([1, 0, 1])
        }
      case "HMAC":
        return algorithm.length === undefined
          ? { name: algorithm.name, hash: algorithm.hash }
          : { name: algorithm.name, hash: algorithm.hash, length: algorithm.length }
      default:
        return algorithm
    }
  }

  const cipherAlgorithm = (algorithm: Crypto.WrapAlgorithm): any => {
    switch (algorithm.name) {
      case "AES-GCM":
        return {
          name: algorithm.name,
          iv: bytes(algorithm.iv),
          tagLength: algorithm.tagLength ?? 128,
          ...(algorithm.additionalData ? { additionalData: bytes(algorithm.additionalData) } : {})
        }
      case "AES-CBC":
        return { name: algorithm.name, iv: bytes(algorithm.iv) }
      case "AES-CTR":
        return { name: algorithm.name, counter: bytes(algorithm.counter), length: algorithm.length }
      case "RSA-OAEP":
        return algorithm.label ? { name: algorithm.name, label: bytes(algorithm.label) } : { name: algorithm.name }
      case "AES-KW":
        return algorithm
    }
  }

  const toBytes = (buffer: ArrayBuffer) => new Uint8Array(buffer)

  const importKey =
    ((format, keyData, algorithm, options) =>
      run("importKey", "Could not import key", () =>
        subtle.importKey(
          format,
          format === "jwk" ? keyData : bytes(keyData as Uint8Array),
          keyAlgorithm(algorithm),
          options.extractable ?? false,
          Array.from(options.usages)
        )).pipe(Effect.map(wrap))) as Crypto.KeyOperations["importKey"]

  const exportKey = ((format, key) =>
    Effect.flatMap(
      unwrap("exportKey", key),
      (native) =>
        run("exportKey", "Could not export key", () => subtle.exportKey(format, native)).pipe(
          Effect.map((exported) => format === "jwk" ? exported : toBytes(exported))
        )
    )) as Crypto.KeyOperations["exportKey"]

  return {
    importKey,
    exportKey,
    generateKey: (algorithm, options) =>
      run(
        "generateKey",
        "Could not generate key",
        () => subtle.generateKey(keyAlgorithm(algorithm), options.extractable ?? false, Array.from(options.usages))
      ).pipe(Effect.map((generated): Crypto.Key | Crypto.KeyPair =>
        generated.publicKey !== undefined
          ? { publicKey: wrap(generated.publicKey), privateKey: wrap(generated.privateKey) }
          : wrap(generated)
      )),
    sign: (algorithm, key, data) =>
      Effect.flatMap(
        unwrap("sign", key),
        (native) =>
          run("sign", "Could not sign data", () => subtle.sign(algorithm, native, bytes(data))).pipe(
            Effect.map(toBytes)
          )
      ),
    verify: (algorithm, key, signature, data) =>
      Effect.flatMap(
        unwrap("verify", key),
        (native) =>
          run("verify", "Could not verify signature", () =>
            subtle.verify(algorithm, native, bytes(signature), bytes(data)))
      ),
    encrypt: (algorithm, key, data) =>
      Effect.flatMap(
        unwrap("encrypt", key),
        (native) =>
          run(
            "encrypt",
            "Could not encrypt data",
            () => subtle.encrypt(cipherAlgorithm(algorithm), native, bytes(data))
          )
            .pipe(Effect.map(toBytes))
      ),
    decrypt: (algorithm, key, data) =>
      Effect.flatMap(
        unwrap("decrypt", key),
        (native) =>
          run(
            "decrypt",
            "Could not decrypt data",
            () => subtle.decrypt(cipherAlgorithm(algorithm), native, bytes(data))
          )
            .pipe(Effect.map(toBytes))
      ),
    deriveBits: (algorithm, baseKey, length) =>
      Effect.flatMap(unwrap("deriveBits", baseKey), (native) => {
        const derive = (params: any) =>
          run("deriveBits", "Could not derive bits", () => subtle.deriveBits(params, native, length)).pipe(
            Effect.map(toBytes)
          )
        switch (algorithm.name) {
          case "ECDH":
          case "X25519":
            return Effect.flatMap(
              unwrap("deriveBits", algorithm.public),
              (publicKey) => derive({ name: algorithm.name, public: publicKey })
            )
          case "HKDF":
            return derive({ ...algorithm, salt: bytes(algorithm.salt), info: bytes(algorithm.info) })
          case "PBKDF2":
            return derive({ ...algorithm, salt: bytes(algorithm.salt) })
        }
      }),
    wrapKey: (format, key, wrappingKey, algorithm) =>
      Effect.flatMap(
        unwrap("wrapKey", key),
        (native) =>
          Effect.flatMap(unwrap("wrapKey", wrappingKey), (wrappingNative) =>
            run(
              "wrapKey",
              "Could not wrap key",
              () => subtle.wrapKey(format, native, wrappingNative, cipherAlgorithm(algorithm))
            ).pipe(Effect.map(toBytes)))
      ),
    unwrapKey: (format, wrappedKey, unwrappingKey, algorithm, keyAlgorithmParams, options) =>
      Effect.flatMap(
        unwrap("unwrapKey", unwrappingKey),
        (native) =>
          run("unwrapKey", "Could not unwrap key", () =>
            subtle.unwrapKey(
              format,
              bytes(wrappedKey),
              native,
              cipherAlgorithm(algorithm),
              keyAlgorithm(keyAlgorithmParams),
              options.extractable ?? false,
              Array.from(options.usages)
            )).pipe(Effect.map(wrap))
      )
  }
}
