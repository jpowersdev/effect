import { assert, describe, it } from "@effect/vitest"
import { Context, DateTime, Effect, Layer, Schema } from "effect"
import { Authorizer, Condition, Permission, Principal } from "effect/permission"
import { Model } from "effect/schema"
import { TestClock } from "effect/testing"
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
  UnitMembership,
  units
} from "./utils.ts"

const TestLayer = Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))

const as =
  (principal: Principal.Principal<Member>) =>
  <A, E>(effect: Effect.Effect<A, E, CurrentPrincipal | Authorizer.Authorizer>): Effect.Effect<A, E> =>
    Effect.provide(Effect.provideService(effect, CurrentPrincipal, principal), TestLayer)

const ShiftId = Schema.String.pipe(Schema.brand("ShiftId"))

class Shift extends Model.Class<Shift>("Shift")({
  id: Model.UuidV4Insert(ShiftId),
  unitId: Schema.String,
  ownerId: Model.GeneratedByApp(Schema.String),
  createdAt: Model.DateTimeInsert,
  updatedAt: Model.DateTimeUpdate
}) {}

const ShiftPermissions = Permission.make(CurrentPrincipal, {
  rules: [
    Permission.rules(CurrentPrincipal, Shift).create("shifts:create", {
      set: ({ principal }) => ({ ownerId: principal.subject.id }),
      check: ({ principal, resource: shift }) => Condition.related(UnitMembership, principal.subject.id, shift.unitId)
    }).action("shifts:update", {
      filter: ({ principal, resource: shift }) => Condition.eq(shift.ownerId, principal.subject.id),
      // createdAt isn't in the update variant, so this passes only if the
      // check sees the whole shift
      check: ({ principal, resource: shift }) =>
        Condition.and(
          Condition.isNotNull(shift.createdAt),
          Condition.related(UnitMembership, principal.subject.id, shift.unitId)
        )
    })
  ]
})

const asShifts =
  (principal: Principal.Principal<Member>) =>
  <A, E>(effect: Effect.Effect<A, E, CurrentPrincipal | Authorizer.Authorizer>): Effect.Effect<A, E> =>
    Effect.provide(
      Effect.provideService(effect, CurrentPrincipal, principal),
      ShiftPermissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))
    )

const denial = <A>(effect: Effect.Effect<A, unknown>) =>
  Effect.flip(effect).pipe(
    Effect.map((error: any) => error._tag === "PermissionDenied" ? `${error._tag}:${error.reason}` : error._tag)
  )

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
          "Unauthenticated"
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

    it.effect("applies limits, expanded through aliases", () =>
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
        // The system principal's shape, from a signed-in principal: `set` replaces the fields
        const created = yield* Permissions.create("swaps:create", {
          id: "s-9",
          unitId: "u-2",
          recipientId: "p-other",
          requesterId: "someone-else",
          status: "approved"
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

    it.effect("builds a Model's insert variant, with its generated fields, before the check", () =>
      Effect.gen(function*() {
        const created = yield* ShiftPermissions.create("shifts:create", { unitId: "u-2" }).pipe(asShifts(nurse))
        assert.strictEqual(created.ownerId, "p-nurse")
        assert.isString(created.id)
        assert.isTrue(DateTime.isDateTime(created.createdAt))
        assert.strictEqual(
          yield* denial(ShiftPermissions.create("shifts:create", { unitId: "u-3" }).pipe(asShifts(nurse))),
          "PermissionDenied:NoPermission"
        )
      }))

    it.effect("denies guests before building the value, and takes preset fields from the system", () =>
      Effect.gen(function*() {
        assert.strictEqual(
          yield* denial(ShiftPermissions.create("shifts:create", { unitId: "u-2" }).pipe(asShifts(Principal.guest))),
          "Unauthenticated"
        )
        const created = yield* ShiftPermissions.create("shifts:create", { unitId: "u-9", ownerId: "rota-import" }).pipe(
          asShifts(Principal.system("rota-import"))
        )
        assert.strictEqual(created.ownerId, "rota-import")
      }))
  })

  describe("update", () => {
    it.effect("builds a Model's update variant from the row, generating its update fields again", () =>
      Effect.gen(function*() {
        const epoch = DateTime.makeUnsafe(0)
        const shift = new Shift({
          id: ShiftId.make("sh-1"),
          unitId: "u-2",
          ownerId: "p-nurse",
          createdAt: epoch,
          updatedAt: epoch
        })
        yield* TestClock.adjust("1 hour")
        const updated = yield* ShiftPermissions.update("shifts:update", shift, {}).pipe(asShifts(nurse))
        assert.deepStrictEqual(Object.keys(updated).sort(), ["id", "ownerId", "unitId", "updatedAt"])
        assert.strictEqual(updated.id, "sh-1")
        assert.strictEqual(updated.ownerId, "p-nurse")
        assert.isTrue(DateTime.isGreaterThan(updated.updatedAt, epoch))
        assert.strictEqual(
          yield* denial(ShiftPermissions.update("shifts:update", shift, { unitId: "u-1" }).pipe(asShifts(nurse))),
          "PermissionDenied:NoPermission"
        )
      }))

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

  describe("lazy attributes", () => {
    interface LazyMember {
      readonly isSuperAdmin: boolean
      readonly homeHospitalId: Principal.Lazy<string>
    }

    class LazyPrincipal extends Context.Service<
      LazyPrincipal,
      Principal.Principal<LazyMember>
    >()("test/permission/LazyPrincipal") {}

    const LazyPermissions = Permission.make(LazyPrincipal, {
      rules: [
        Permission.rules(LazyPrincipal, Unit).action("units:read", {
          filter: ({ principal, resource: unit }) =>
            Condition.or(
              principal.attributes.isSuperAdmin,
              Condition.eq(unit.hospitalId, principal.attributes.homeHospitalId)
            )
        }).create("units:create", {
          check: () => Condition.always,
          // Reading a lazy attribute is an effect, so `set` returns one
          set: ({ principal }) => Effect.map(principal.attributes.homeHospitalId, (hospitalId) => ({ hospitalId }))
        })
      ]
    })

    const signIn = <E>(isSuperAdmin: boolean, homeHospitalId: Effect.Effect<string, E>) => {
      const loads = { count: 0 }
      const principal = Principal.make({
        subject: "p-1",
        attributes: {
          isSuperAdmin,
          homeHospitalId: Effect.suspend(() => {
            loads.count++
            return homeHospitalId
          })
        }
      })
      const run = <A, E2>(effect: Effect.Effect<A, E2, LazyPrincipal | Authorizer.Authorizer>) =>
        Effect.provide(Effect.provideService(effect, LazyPrincipal, principal), LazyPermissions.layer)
      return { principal, loads, run }
    }

    it.effect("loads an attribute once per principal, and only for rules that reach it", () =>
      Effect.gen(function*() {
        const [u1, u2] = units
        const admin = signIn(true, Effect.succeed("h-9"))
        yield* admin.run(LazyPermissions.require("units:read", u2))
        assert.isTrue(Condition.isAlways(yield* admin.run(LazyPermissions.filter("units:read"))))
        assert.strictEqual(admin.loads.count, 0)

        const nurse = signIn(false, Effect.succeed("h-1"))
        yield* nurse.run(LazyPermissions.require("units:read", u1))
        assert.strictEqual(
          yield* denial(nurse.run(LazyPermissions.require("units:read", u2))),
          "PermissionDenied:NoPermission"
        )
        const filter = yield* nurse.run(LazyPermissions.filter("units:read"))
        assert.strictEqual(filter._tag === "Compare" && filter.right, "h-1")
        assert.strictEqual(yield* nurse.principal.attributes.homeHospitalId, "h-1")
        assert.strictEqual(nurse.loads.count, 1)
      }))

    it.effect("runs a set that reads a lazy attribute", () =>
      Effect.gen(function*() {
        const nurse = signIn(false, Effect.succeed("h-1"))
        const created = yield* nurse.run(LazyPermissions.create("units:create", { id: "u-9", name: "Wards" }))
        assert.strictEqual(created.hospitalId, "h-1")
      }))

    it.effect("fails with PermissionUnavailable when an attribute can't load", () =>
      Effect.gen(function*() {
        const nurse = signIn(false, Effect.fail("database down"))
        assert.strictEqual(
          yield* denial(nurse.run(LazyPermissions.require("units:read", units[0]))),
          "PermissionUnavailable"
        )
        assert.strictEqual(yield* denial(nurse.run(LazyPermissions.filter("units:read"))), "PermissionUnavailable")
        assert.strictEqual(nurse.loads.count, 1)
      }))
  })

  describe("rules", () => {
    it("rejects actions that refer to actions not declared before them", () => {
      assert.throws(
        () =>
          Permission.rules(CurrentPrincipal, Unit)
            // @ts-expect-error -- "b" is not declared yet
            .action("a", { filter: ({ allowed }) => allowed("b") }),
        /not an action declared before it/
      )
    })

    it("rejects actions declared twice", () => {
      const rules = Permission.rules(CurrentPrincipal, Unit).action("a", { filter: () => Condition.always })
      // @ts-expect-error -- "a" is already declared
      assert.throws(() => rules.action("a", { filter: () => Condition.always }), /declared twice/)
      assert.throws(() => Permission.make(CurrentPrincipal, { rules: [rules, rules] }), /declared twice/)
    })
  })
})
