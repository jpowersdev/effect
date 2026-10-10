import { assert, describe, it } from "@effect/vitest"
import * as Effect from "effect/Effect"
import { type JsonWebAlgorithm, JsonWebEncryption, JsonWebKey } from "effect/jose"
import * as Redacted from "effect/Redacted"
import { JoseLive, text, utf8 } from "./utils.ts"

const plaintext = "Live long and prosper."

const contentEncryption = ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"] as const

const recipientFor = (
  alg: JsonWebAlgorithm.KeyManagementAlgorithm,
  enc: JsonWebAlgorithm.ContentEncryptionAlgorithm
) =>
  Effect.gen(function*() {
    const keys = yield* JsonWebKey.JsonWebKey
    if (alg === "dir") {
      const key = yield* keys.generateSecret(enc)
      return { encrypt: key, decrypt: key }
    }
    if (alg.startsWith("PBES2")) {
      const password = utf8("correct horse battery staple")
      return { encrypt: password, decrypt: password }
    }
    if (alg.startsWith("A")) {
      const key = yield* keys.generateSecret(alg)
      return { encrypt: key, decrypt: key }
    }
    const { privateKey, publicKey } = yield* keys.generateKeyPair(alg)
    return { encrypt: publicKey, decrypt: privateKey }
  })

describe("JsonWebEncryption", () => {
  // RFC 7516 Appendix A.3: A128KW with A128CBC-HS256
  it.effect("reproduces the RFC 7516 A.3 example exactly", () =>
    Effect.gen(function*() {
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const kek = { kty: "oct", k: "GawgguFyGrWKav7AX4VKUg" }
      const cek = new Uint8Array([
        4,
        211,
        31,
        197,
        84,
        157,
        252,
        254,
        11,
        100,
        157,
        250,
        63,
        170,
        106,
        206,
        107,
        124,
        212,
        45,
        111,
        107,
        9,
        219,
        200,
        177,
        0,
        240,
        143,
        156,
        44,
        207
      ])
      const iv = new Uint8Array([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101])
      const token = yield* jwe.encryptCompact(plaintext, {
        key: kek,
        protectedHeader: { alg: "A128KW", enc: "A128CBC-HS256" },
        cek,
        iv
      })
      assert.strictEqual(
        Redacted.value(token),
        "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
          "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
          "AxY8DCtDaGlsbGljb3RoZQ." +
          "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
          "U0m_YmjN04DJvceFICbCVQ"
      )
      const { plaintext: decrypted } = yield* jwe.decryptCompact(token, kek)
      assert.strictEqual(text(decrypted), plaintext)
    }).pipe(Effect.provide(JoseLive)))

  const keyManagement = [
    "dir",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "A128KW",
    "A256KW",
    "A128GCMKW",
    "PBES2-HS256+A128KW"
  ] as const

  for (const alg of keyManagement) {
    for (const enc of contentEncryption) {
      it.effect(`round-trips ${alg} + ${enc}`, () =>
        Effect.gen(function*() {
          const jwe = yield* JsonWebEncryption.JsonWebEncryption
          const recipient = yield* recipientFor(alg, enc)
          const token = yield* jwe.encryptCompact(plaintext, {
            key: recipient.encrypt,
            protectedHeader: { alg, enc }
          })
          const { plaintext: decrypted } = yield* jwe.decryptCompact(token, recipient.decrypt, {
            keyManagementAlgorithms: [alg]
          })
          assert.strictEqual(text(decrypted), plaintext)
        }).pipe(Effect.provide(JoseLive)))
    }
  }

  it.effect("rejects PBES2 unless allowed and bounds its iteration count", () =>
    Effect.gen(function*() {
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const password = utf8("pw")
      const token = yield* jwe.encryptCompact(plaintext, {
        key: password,
        protectedHeader: { alg: "PBES2-HS256+A128KW", enc: "A128GCM" },
        keyManagementParameters: { p2c: 20_000 }
      })
      const notAllowed = yield* Effect.flip(jwe.decryptCompact(token, password))
      assert.strictEqual(notAllowed._tag, "AlgorithmNotAllowedError")
      const tooMany = yield* Effect.flip(
        jwe.decryptCompact(token, password, { keyManagementAlgorithms: ["PBES2-HS256+A128KW"] })
      )
      assert.strictEqual(tooMany._tag, "MalformedJweError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("fails uniformly when the wrong key is used", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const a = yield* keys.generateKeyPair("RSA-OAEP-256")
      const b = yield* keys.generateKeyPair("RSA-OAEP-256")
      const token = yield* jwe.encryptCompact(plaintext, {
        key: a.publicKey,
        protectedHeader: { alg: "RSA-OAEP-256", enc: "A256GCM" }
      })
      const error = yield* Effect.flip(jwe.decryptCompact(token, b.privateKey))
      assert.strictEqual(error._tag, "DecryptionError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("encrypts to several recipients with general JSON", () =>
    Effect.gen(function*() {
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const rsa = yield* recipientFor("RSA-OAEP-256", "A256GCM")
      const kw = yield* recipientFor("A256KW", "A256GCM")
      const encrypted = yield* jwe.encryptGeneral(plaintext, {
        protectedHeader: { enc: "A256GCM" },
        recipients: [
          { key: rsa.encrypt, unprotectedHeader: { alg: "RSA-OAEP-256" } },
          { key: kw.encrypt, unprotectedHeader: { alg: "A256KW" } }
        ]
      })
      for (const recipient of [rsa, kw]) {
        const { plaintext: decrypted } = yield* jwe.decryptGeneral(encrypted, recipient.decrypt)
        assert.strictEqual(text(decrypted), plaintext)
      }
    }).pipe(Effect.provide(JoseLive)))

  it.effect("rejects compressed content", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const key = yield* keys.generateSecret("A128KW")
      const error = yield* Effect.flip(jwe.encryptCompact(plaintext, {
        key,
        protectedHeader: { alg: "A128KW", enc: "A128GCM", zip: "DEF" }
      }))
      assert.strictEqual(error._tag, "UnsupportedJweHeaderError")
    }).pipe(Effect.provide(JoseLive)))

  it.effect("accepts a private JWK as the ECDH-ES ephemeral key", () =>
    Effect.gen(function*() {
      const keys = yield* JsonWebKey.JsonWebKey
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const recipient = yield* keys.generateKeyPair("ECDH-ES")
      const ephemeral = yield* keys.generateKeyPair("ECDH-ES", { extractable: true })
      const epk = yield* keys.exportPrivateJwk(ephemeral.privateKey)
      const token = yield* jwe.encryptCompact(plaintext, {
        key: recipient.publicKey,
        protectedHeader: { alg: "ECDH-ES", enc: "A256GCM" },
        keyManagementParameters: { epk }
      })
      const { plaintext: decrypted, protectedHeader } = yield* jwe.decryptCompact(
        token,
        recipient.privateKey
      )
      assert.strictEqual(text(decrypted), plaintext)
      assert.deepStrictEqual((protectedHeader!.epk as any).x, Redacted.value(epk).x)
      assert.isUndefined((protectedHeader!.epk as any).d)
    }).pipe(Effect.provide(JoseLive)))

  it.effect("keeps per-recipient ECDH-ES parameters out of the shared header", () =>
    Effect.gen(function*() {
      const jwe = yield* JsonWebEncryption.JsonWebEncryption
      const a = yield* recipientFor("ECDH-ES+A128KW", "A128GCM")
      const b = yield* recipientFor("ECDH-ES+A128KW", "A128GCM")
      const encrypted = yield* jwe.encryptGeneral(plaintext, {
        protectedHeader: { enc: "A128GCM", alg: "ECDH-ES+A128KW" },
        recipients: [{ key: a.encrypt }, { key: b.encrypt }]
      })
      assert.notInclude(atob(encrypted.protected!.replace(/-/g, "+").replace(/_/g, "/")), "epk")
      for (const recipient of [a, b]) {
        const { plaintext: decrypted } = yield* jwe.decryptGeneral(encrypted, recipient.decrypt)
        assert.strictEqual(text(decrypted), plaintext)
      }
    }).pipe(Effect.provide(JoseLive)))
})
