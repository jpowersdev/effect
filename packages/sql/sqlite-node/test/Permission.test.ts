import { SqliteClient } from "@effect/sql-sqlite-node"
import { assert, describe, it } from "@effect/vitest"
import { Context, Effect, Layer, Schema } from "effect"
import { Authorizer, Condition, Permission, PermissionSql, Principal } from "effect/permission"
import { Reactivity } from "effect/reactivity"
import * as SqlClient from "effect/sql/SqlClient"

class Unit extends Schema.Class<Unit>("Unit")({
  id: Schema.String,
  hospitalId: Schema.String
}) {}

interface Member {
  readonly homeHospitalId: string
  readonly isSuperAdmin: boolean
}

class CurrentPrincipal extends Context.Service<
  CurrentPrincipal,
  Principal.Principal<Member>
>()("test/CurrentPrincipal") {}

const UnitMembership = Condition.relation<string, string>("unit:member")

const Permissions = Permission.make(CurrentPrincipal, {
  rules: [
    Permission.rules(CurrentPrincipal, Unit, {
      "units:read": {
        filter: ({ principal, resource: unit }) =>
          Condition.or(
            principal.attributes.isSuperAdmin,
            Condition.eq(unit.hospitalId, principal.attributes.homeHospitalId),
            Condition.related(UnitMembership, principal.subject.id, unit.id)
          )
      }
    })
  ]
})

const units = [
  new Unit({ id: "u-1", hospitalId: "h-1" }),
  new Unit({ id: "u-2", hospitalId: "h-2" }),
  new Unit({ id: "u-3", hospitalId: "h-3" })
]

const principals = [
  Principal.make({ subject: "p-nurse", attributes: { homeHospitalId: "h-1", isSuperAdmin: false } }),
  Principal.make({ subject: "p-float", attributes: { homeHospitalId: "h-9", isSuperAdmin: false } }),
  Principal.make({ subject: "p-admin", attributes: { homeHospitalId: "h-9", isSuperAdmin: true } })
]

const Seeded = Layer.effectDiscard(Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient
  yield* sql`CREATE TABLE unit (id TEXT PRIMARY KEY, hospital_id TEXT NOT NULL)`
  yield* sql`CREATE TABLE profile_unit (profile_id TEXT NOT NULL, unit_id TEXT NOT NULL)`
  for (const unit of units) {
    yield* sql`INSERT INTO unit ${sql.insert({ id: unit.id, hospital_id: unit.hospitalId })}`
  }
  yield* sql`INSERT INTO profile_unit ${
    sql.insert([
      { profile_id: "p-nurse", unit_id: "u-2" },
      { profile_id: "p-float", unit_id: "u-3" }
    ])
  }`
}))

// The service closes over the SQL client and the mappings, and also answers
// the authorizer's relation lookups
class PermissionsSql extends PermissionSql.Service<PermissionsSql>()("test/PermissionsSql", {
  permissions: Permissions,
  tables: [PermissionSql.table(Unit, "unit", { hospitalId: "hospital_id" })],
  relations: [
    PermissionSql.relation(UnitMembership, { table: "profile_unit", subject: "profile_id", object: "unit_id" })
  ]
}) {}

const TestLayer = Permissions.layer.pipe(
  Layer.provideMerge(PermissionsSql.layer),
  Layer.provideMerge(Seeded),
  Layer.provideMerge(SqliteClient.layer({ filename: ":memory:" })),
  Layer.provide(Reactivity.layer)
)

const visibleUnitIds = Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient
  const visible = yield* (yield* PermissionsSql).filter("units:read")
  const rows = yield* sql<{ readonly id: string }>`SELECT id FROM unit WHERE ${visible} ORDER BY id`
  return rows.map((row) => row.id)
})

describe("Permission with SQLite", () => {
  it.effect("returns only the rows the principal may see", () =>
    Effect.gen(function*() {
      const [nurse, float, admin] = principals
      assert.deepStrictEqual(yield* visibleUnitIds.pipe(Effect.provideService(CurrentPrincipal, nurse)), ["u-1", "u-2"])
      assert.deepStrictEqual(yield* visibleUnitIds.pipe(Effect.provideService(CurrentPrincipal, float)), ["u-3"])
      assert.deepStrictEqual(yield* visibleUnitIds.pipe(Effect.provideService(CurrentPrincipal, admin)), [
        "u-1",
        "u-2",
        "u-3"
      ])
      assert.deepStrictEqual(yield* visibleUnitIds.pipe(Effect.provideService(CurrentPrincipal, Principal.guest)), [])
    }).pipe(Effect.provide(TestLayer)))

  it.effect("agrees with the single-record check, which looks relations up in SQL", () =>
    Effect.gen(function*() {
      for (const principal of principals) {
        const visible = yield* visibleUnitIds.pipe(Effect.provideService(CurrentPrincipal, principal))
        for (const unit of units) {
          const decision = yield* Permissions.can("units:read", unit).pipe(
            Effect.provideService(CurrentPrincipal, principal)
          )
          assert.strictEqual(
            Authorizer.isAllow(decision),
            visible.includes(unit.id),
            `${principal.subject.id} on ${unit.id}`
          )
        }
      }
    }).pipe(Effect.provide(TestLayer)))
})
