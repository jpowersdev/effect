/**
 * Compiles permission conditions into SQL, and answers relation lookups from
 * SQL tables.
 *
 * {@link table} maps a resource schema to its table and columns, and
 * {@link relation} maps a `Condition.Relation` to the table that stores its
 * facts. {@link where} compiles a simplified condition into a
 * `Statement.Fragment`; {@link filter} does that for an action's plan, so a
 * list query returns only what the principal may see.
 *
 * **Details**
 *
 * Compiled fragments deny by default: a condition that can never hold is
 * `1=0`, and so is an empty `or`. Columns are qualified with the resource's
 * table name, and relation lookups become `EXISTS` subqueries.
 *
 * **Gotchas**
 *
 * `Condition.custom` conditions cannot be compiled. Compiling one is a defect,
 * so keep custom conditions off actions used to filter lists.
 *
 * **Example** (Filtering a list query)
 *
 * ```ts
 * const visible = yield* PermissionSql.filter(Permissions, "units:read")
 * const units = yield* sql`SELECT * FROM unit WHERE ${visible} ORDER BY name`
 * ```
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Context from "../Context.ts"
import * as Effect from "../Effect.ts"
import * as Layer from "../Layer.ts"
import type * as Schema from "../Schema.ts"
import * as SqlClient from "../sql/SqlClient.ts"
import * as Statement from "../sql/Statement.ts"
import * as Authorizer from "./Authorizer.ts"
import * as Condition from "./Condition.ts"
import type * as Permission from "./Permission.ts"
import * as PermissionError from "./PermissionError.ts"

/**
 * Where a resource type is stored: its table, and the column for each field
 * that differs from the field's name.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Table<S extends Schema.Top = Schema.Top> {
  readonly resource: S
  readonly name: string
  readonly columns: { readonly [K in keyof S["Type"]]?: string | undefined }
}

/**
 * Maps a resource schema to its table. Fields without a column mapping use
 * their own name, so the SQL client's name transform still applies.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const table = <S extends Schema.Top>(
  resource: S,
  name: string,
  columns: { readonly [K in keyof S["Type"]]?: string | undefined } = {}
): Table<S> => ({ resource, name, columns })

/**
 * Where a relation's facts are stored: a table with one column for the
 * subject and one for the object.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface RelationTable {
  readonly relation: Condition.Relation<any, any>
  readonly table: string
  readonly subject: string
  readonly object: string
}

/**
 * Maps a relation to the table that stores its facts.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const relation = (
  relation: Condition.Relation<any, any>,
  options: {
    readonly table: string
    readonly subject: string
    readonly object: string
  }
): RelationTable => ({ relation, ...options })

/**
 * The table mappings used by {@link filter} and the SQL relation store.
 *
 * @stability experimental
 * @category services
 * @since 4.1.3
 */
export class Mappings extends Context.Service<
  Mappings,
  {
    readonly tables: ReadonlyMap<Schema.Top, Table>
    readonly relations: ReadonlyMap<Condition.Relation<any, any>, RelationTable>
  }
>()("effect/permission/PermissionSql/Mappings") {}

// -----------------------------------------------------------------------------
// Compilation
// -----------------------------------------------------------------------------

const operators: Record<Condition.Operator, string> = {
  eq: " = ",
  neq: " <> ",
  lt: " < ",
  lte: " <= ",
  gt: " > ",
  gte: " >= "
}

type Part = string | Statement.Fragment

const segmentsOf = (part: Part): ReadonlyArray<Statement.Segment> =>
  typeof part === "string" ? [Statement.literal(part)] : part.segments

const sequence = (...parts: ReadonlyArray<Part>): Statement.Fragment => Statement.fragment(parts.flatMap(segmentsOf))

const anyOf = Statement.join(" OR ", true, "1=0")
const allOf = Statement.join(" AND ", true, "1=1")

const compile = (
  condition: Condition.Condition<any>,
  table: Table,
  relations: ReadonlyMap<Condition.Relation<any, any>, RelationTable>
): Statement.Fragment => {
  let aliases = 0

  const qualified = (tableName: string, column: string): Statement.Fragment =>
    Statement.fragment([Statement.identifier(tableName), Statement.literal("."), Statement.identifier(column)])

  const column = (ref: Condition.Ref<unknown>): Statement.Fragment => {
    const { path, source } = Condition.refPath(ref)
    if (source === "principal") {
      throw new Error(
        `PermissionSql.where: principal.${path.join(".")} is not filled in; call Condition.simplify first`
      )
    }
    if (path.length !== 1) {
      throw new Error(`PermissionSql.where: nested field resource.${path.join(".")} cannot be compiled`)
    }
    const field = path[0]
    return qualified(table.name, (table.columns as Record<string, string | undefined>)[field] ?? field)
  }

  const operand = (value: Condition.Operand<unknown>): Statement.Fragment =>
    Condition.isRef(value) ? column(value) : Statement.fragment([Statement.parameter(value)])

  const go = (node: Condition.Condition<any>): Statement.Fragment => {
    switch (node._tag) {
      case "Literal":
        return sequence(node.value === true ? "1=1" : node.value === false ? "1=0" : "NULL")
      case "Truthy":
        return Condition.isRef(node.value) ? column(node.value) : go(Condition.simplify(node, undefined))
      case "Compare":
        return sequence(operand(node.left), operators[node.operator], operand(node.right))
      case "OneOf": {
        if (Condition.isRef(node.list)) {
          throw new Error("PermissionSql.where: oneOf over a list field cannot be compiled")
        }
        const items = node.list.filter((item) => Condition.isRef(item) || (item !== null && item !== undefined))
        if (items.length === 0) return sequence("1=0")
        return sequence(operand(node.value), " IN (", Statement.join(", ", false)(items.map(operand)), ")")
      }
      case "IsNull":
        return sequence(operand(node.value), " IS NULL")
      case "Not":
        return sequence("NOT (", go(node.condition), ")")
      case "And":
        return allOf(node.conditions.map(go))
      case "Or":
        return anyOf(node.conditions.map(go))
      case "Related": {
        const mapping = relations.get(node.relation)
        if (mapping === undefined) {
          throw new Error(`PermissionSql.where: no table for relation "${node.relation.name}"`)
        }
        const alias = `permission_relation_${aliases++}`
        return sequence(
          "EXISTS (SELECT 1 FROM ",
          Statement.fragment([Statement.identifier(mapping.table)]),
          " AS ",
          Statement.fragment([Statement.identifier(alias)]),
          " WHERE ",
          qualified(alias, mapping.subject),
          " = ",
          operand(node.subject),
          " AND ",
          qualified(alias, mapping.object),
          " = ",
          operand(node.object),
          ")"
        )
      }
      case "Custom":
        throw new Error(`PermissionSql.where: custom condition "${node.name}" cannot be compiled`)
    }
  }
  return go(condition)
}

/**
 * Compiles a condition over a resource's fields into a SQL fragment for its
 * table.
 *
 * **Gotchas**
 *
 * The condition must refer only to resource fields, as returned by
 * `Condition.simplify` or `Permissions.filter`. Principal references, custom
 * conditions, nested fields, `oneOf` over a list field, and relations without
 * a mapping are defects.
 *
 * @stability experimental
 * @category compilation
 * @since 4.1.3
 */
export const where = (
  condition: Condition.Condition<any>,
  table: Table,
  options?: {
    readonly relations?: Iterable<RelationTable> | undefined
  }
): Effect.Effect<Statement.Fragment> =>
  Effect.sync(() =>
    compile(
      condition,
      table,
      new Map(Array.from(options?.relations ?? [], (mapping) => [mapping.relation, mapping] as const))
    )
  )

/**
 * Compiles the plan for an action into a SQL fragment for the action's
 * resource table, using the mappings from {@link layer}.
 *
 * @stability experimental
 * @category compilation
 * @since 4.1.3
 */
export const filter = <I, A, U extends Permission.Any, Ac extends Permission.ActionsOf<U>>(
  permissions: Permission.Permissions<I, A, U>,
  action: Ac
): Effect.Effect<Statement.Fragment, PermissionError.PermissionUnavailable, I | Authorizer.Authorizer | Mappings> =>
  Effect.gen(function*() {
    const condition = yield* permissions.filter(action)
    const mappings = yield* Mappings
    const resource = permissions.actions.get(action)!.resource
    const mapping = mappings.tables.get(resource)
    if (mapping === undefined) {
      return yield* Effect.die(new Error(`PermissionSql.filter: no table for the resource of "${action}"`))
    }
    return yield* Effect.sync(() => compile(condition, mapping, mappings.relations))
  })

const makeMappings = (options: {
  readonly tables: Iterable<Table<any>>
  readonly relations?: Iterable<RelationTable> | undefined
}): Mappings["Service"] => ({
  tables: new Map(Array.from(options.tables, (mapping) => [mapping.resource, mapping] as const)),
  relations: new Map(Array.from(options.relations ?? [], (mapping) => [mapping.relation, mapping] as const))
})

/**
 * Provides only the table mappings, for compiling filters when relation facts
 * are looked up elsewhere.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layerMappings = (options: {
  readonly tables: Iterable<Table<any>>
  readonly relations?: Iterable<RelationTable> | undefined
}): Layer.Layer<Mappings> => Layer.succeed(Mappings, makeMappings(options))

/**
 * Provides the table mappings, and a relation store that looks up relation
 * facts in their SQL tables.
 *
 * @stability experimental
 * @category layers
 * @since 4.1.3
 */
export const layer = (options: {
  readonly tables: Iterable<Table<any>>
  readonly relations?: Iterable<RelationTable> | undefined
}): Layer.Layer<Mappings, never, SqlClient.SqlClient> => {
  const mappings = makeMappings(options)
  const relations = mappings.relations
  const store = Layer.effect(
    Authorizer.Relations,
    Effect.gen(function*() {
      const sql = yield* SqlClient.SqlClient
      return {
        has: (relation, subject, object) => {
          const mapping = relations.get(relation)
          if (mapping === undefined) {
            return Effect.logWarning(`No table is mapped for relation "${relation.name}"`).pipe(
              Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
            )
          }
          return sql<{ readonly found: number }>`SELECT 1 AS found FROM ${sql(mapping.table)} WHERE ${
            sql(mapping.subject)
          } = ${subject} AND ${sql(mapping.object)} = ${object} LIMIT 1`.pipe(
            Effect.map((rows) => rows.length > 0),
            Effect.catchTag(
              "SqlError",
              (error) =>
                Effect.logWarning(`Looking up relation "${relation.name}" failed`, error).pipe(
                  Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
                )
            )
          )
        }
      } satisfies Authorizer.RelationStore
    })
  )
  return Layer.merge(Layer.succeed(Mappings, mappings), store)
}
