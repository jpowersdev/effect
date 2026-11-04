import { assert, describe, it } from "@effect/vitest"
import { Effect, Exit, Layer } from "effect"
import { Authorizer, Condition, Permission, PermissionSql } from "effect/permission"
import * as Statement from "effect/sql/Statement"
import { admin, CurrentPrincipal, memberships, nurse, Permissions, Unit, UnitMembership } from "./utils.ts"

const UnitTable = PermissionSql.table(Unit, "unit", { hospitalId: "hospital_id" })
const Memberships = PermissionSql.relation(UnitMembership, {
  table: "profile_unit",
  subject: "profile_id",
  object: "unit_id"
})

const TestLayer = Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))

const compile = (fragment: Statement.Fragment) => Statement.makeCompilerSqlite().compile(fragment, false)

const plan = (principal: typeof nurse) =>
  Permissions.filter("units:read").pipe(Effect.provideService(CurrentPrincipal, principal))

describe("PermissionSql", () => {
  it.effect("compiles a plan into a qualified, parameterized fragment", () =>
    Effect.gen(function*() {
      const fragment = yield* PermissionSql.where(yield* plan(nurse), UnitTable, { relations: [Memberships] })
      assert.deepStrictEqual(compile(fragment), [
        `("unit"."hospital_id" = ? OR EXISTS (SELECT 1 FROM "profile_unit" AS "permission_relation_0" WHERE "permission_relation_0"."profile_id" = ? AND "permission_relation_0"."unit_id" = "unit"."id"))`,
        ["h-1", "p-nurse"]
      ])
    }).pipe(Effect.provide(TestLayer)))

  it.effect("compiles an unconditional plan to 1=1", () =>
    Effect.gen(function*() {
      assert.deepStrictEqual(compile(yield* PermissionSql.where(yield* plan(admin), UnitTable)), ["1=1", []])
    }).pipe(Effect.provide(TestLayer)))

  it.effect("denies by default when nothing can match", () =>
    Effect.gen(function*() {
      assert.deepStrictEqual(compile(yield* PermissionSql.where(Condition.never, UnitTable)), ["1=0", []])
      assert.deepStrictEqual(compile(yield* PermissionSql.where(Condition.or(), UnitTable)), ["1=0", []])
      const { resource } = Condition.refs<unknown, Unit>()
      assert.deepStrictEqual(compile(yield* PermissionSql.where(Condition.oneOf(resource.id, []), UnitTable)), [
        "1=0",
        []
      ])
    }))

  it.effect("refuses to compile custom conditions and principal references", () =>
    Effect.gen(function*() {
      const rules = Permission.rules(CurrentPrincipal, Unit, {
        "units:audit": { filter: () => Condition.custom("audit", () => Effect.succeed(true)) },
        "units:raw": {
          filter: ({ principal, resource }) => Condition.eq(resource.hospitalId, principal.attributes.homeHospitalId)
        }
      })
      for (const action of ["units:audit", "units:raw"]) {
        const exit = yield* Effect.exit(PermissionSql.where(rules.actions.get(action)!.filter!, UnitTable))
        assert.isTrue(Exit.hasDies(exit), action)
      }
    }))
})
