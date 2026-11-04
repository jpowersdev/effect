import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer } from "effect"
import { Authorizer, Condition, Permission, Principal } from "effect/permission"
import {
  admin,
  CurrentPrincipal,
  manager,
  type Member,
  memberships,
  nurse,
  otherNurse,
  Permissions,
  swap,
  Unit,
  units
} from "./utils.ts"

const TestLayer = Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))

const as =
  (principal: Principal.Principal<Member>) =>
  <A, E>(effect: Effect.Effect<A, E, CurrentPrincipal | Authorizer.Authorizer>): Effect.Effect<A, E> =>
    Effect.provide(Effect.provideService(effect, CurrentPrincipal, principal), TestLayer)

const denial = <A>(effect: Effect.Effect<A, unknown>) =>
  Effect.flip(effect).pipe(Effect.map((error: any) => `${error._tag}:${error.reason}`))

describe("Permission", () => {
  describe("require", () => {
    it.effect("allows through attributes, relations, or a super-admin flag", () =>
      Effect.gen(function*() {
        const [u1, u2, u3] = units
        assert.strictEqual(yield* Permissions.require("units:read", u1).pipe(as(nurse)), u1) // home hospital
        assert.strictEqual(yield* Permissions.require("units:read", u2).pipe(as(nurse)), u2) // unit membership
        assert.strictEqual(
          yield* denial(Permissions.require("units:read", u3).pipe(as(nurse))),
          "PermissionDenied:NoPermission"
        )
        assert.strictEqual(yield* Permissions.require("units:read", u3).pipe(as(admin)), u3)
      }))

    it.effect("denies guests and allows the system", () =>
      Effect.gen(function*() {
        const [u1] = units
        assert.strictEqual(
          yield* denial(Permissions.require("units:read", u1).pipe(as(Principal.guest))),
          "PermissionDenied:Unauthenticated"
        )
        assert.strictEqual(yield* Permissions.require("units:read", u1).pipe(as(Principal.system("nightly-sync"))), u1)
      }))

    it.effect("lets forbid override filter", () =>
      Effect.gen(function*() {
        const accepted = swap({ status: "accepted" })
        yield* Permissions.require("swaps:approve", accepted).pipe(as(manager))
        const impersonating = Principal.withActor(manager, "support-1")
        assert.strictEqual(
          yield* denial(Permissions.require("swaps:approve", accepted).pipe(as(impersonating))),
          "PermissionDenied:Forbidden"
        )
      }))

    it.effect("applies limits, expanded through action groups", () =>
      Effect.gen(function*() {
        const viaText = Principal.withLimit(nurse, ["swaps:respond"])
        yield* Permissions.require("swaps:accept", swap({})).pipe(as(viaText))
        assert.strictEqual(
          yield* denial(Permissions.require("units:read", units[0]).pipe(as(viaText))),
          "PermissionDenied:Limit"
        )
        const managerViaText = Principal.withLimit(manager, ["swaps:respond"])
        assert.strictEqual(
          yield* denial(Permissions.require("swaps:approve", swap({ status: "accepted" })).pipe(as(managerViaText))),
          "PermissionDenied:Limit"
        )
      }))
  })

  describe("can", () => {
    it.effect("returns the decision instead of failing", () =>
      Effect.gen(function*() {
        const decision = yield* Permissions.can("units:read", units[2]).pipe(as(nurse))
        assert.deepStrictEqual(decision, Authorizer.deny("units:read", "NoPermission"))
      }))
  })

  describe("filter", () => {
    it.effect("returns the condition a resource must satisfy", () =>
      Effect.gen(function*() {
        const condition = yield* Permissions.filter("units:read").pipe(as(nurse))
        const visible = yield* Effect.filter(units, (unit) =>
          Condition.evaluate(condition, {
            principal: undefined,
            resource: unit,
            related: (_relation, subject, object) =>
              Effect.succeed(memberships.some((m) => m.subject === subject && m.object === object))
          }))
        assert.deepStrictEqual(visible.map((unit) => unit.id), ["u-1", "u-2"])
        assert.isTrue(Condition.isAlways(yield* Permissions.filter("units:read").pipe(as(admin))))
      }))

    it.effect("plans create-only actions from their check", () =>
      Effect.gen(function*() {
        assert.isFalse(Condition.isNever(yield* Permissions.filter("swaps:create").pipe(as(nurse))))
        assert.isTrue(Condition.isNever(yield* Permissions.filter("swaps:create").pipe(as(Principal.guest))))
      }))

    it.effect("returns never when the principal could never pass", () =>
      Effect.gen(function*() {
        assert.isTrue(Condition.isNever(yield* Permissions.filter("units:update").pipe(as(nurse))))
        assert.isTrue(Condition.isNever(yield* Permissions.filter("units:read").pipe(as(Principal.guest))))
      }))
  })

  describe("create", () => {
    it.effect("applies presets over the payload, then checks the result", () =>
      Effect.gen(function*() {
        const created = yield* Permissions.create("swaps:create", {
          id: "s-9",
          unitId: "u-2",
          recipientId: "p-other",
          requesterId: "someone-else"
        }).pipe(as(nurse))
        assert.strictEqual(created.requesterId, "p-nurse")
        assert.strictEqual(created.status, "pending")
        assert.strictEqual(
          yield* denial(
            Permissions.create("swaps:create", { id: "s-9", unitId: "u-3", recipientId: "p-other" }).pipe(as(nurse))
          ),
          "PermissionDenied:NoPermission"
        )
      }))
  })

  describe("update", () => {
    it.effect("checks the resource before and after the change", () =>
      Effect.gen(function*() {
        const [u1] = units
        const renamed = yield* Permissions.update("units:update", u1, { name: "Intensive Care" }).pipe(as(manager))
        assert.strictEqual(renamed.name, "Intensive Care")
        assert.instanceOf(renamed, Unit)
        // A manager who reaches u-1 only through their home hospital can't move it to a hospital they can't reach
        const homeManager = Principal.make({ subject: "p-home", attributes: { ...manager.attributes } })
        assert.strictEqual(
          yield* denial(Permissions.update("units:update", u1, { hospitalId: "h-3" }).pipe(as(homeManager))),
          "PermissionDenied:NoPermission"
        )
        // The direct member of u-1 still reaches it after the move
        yield* Permissions.update("units:update", u1, { hospitalId: "h-3" }).pipe(as(manager))
        assert.strictEqual(
          yield* denial(Permissions.update("units:update", u1, { name: "x" }).pipe(as(otherNurse))),
          "PermissionDenied:NoPermission"
        )
      }))
  })

  describe("rules", () => {
    it("rejects actions that refer to themselves through allowed", () => {
      assert.throws(
        () =>
          Permission.rules(CurrentPrincipal, Unit, {
            "a": { filter: ({ allowed }) => allowed("b") },
            "b": { filter: ({ allowed }) => allowed("a") }
          }),
        /refers to itself/
      )
    })

    it("rejects actions declared twice", () => {
      const rules = Permission.rules(CurrentPrincipal, Unit, { "a": { filter: () => Condition.always } })
      assert.throws(() => Permission.make(CurrentPrincipal, { rules: [rules, rules] }), /declared twice/)
    })
  })
})
