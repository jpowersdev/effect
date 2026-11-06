/**
 * Compiles permission conditions into SQL, and answers relation lookups from
 * SQL tables.
 *
 * {@link table} maps a resource schema to its table and columns, and
 * {@link relation} maps a `Condition.Relation` to the table that stores its
 * facts. {@link Service} declares the application's service: its layer closes
 * over the SQL client and the mappings, its `filter` compiles an action's plan
 * into a `Statement.Fragment` so a list query returns only what the principal
 * may see, and it answers the authorizer's relation lookups.
 *
 * **Details**
 *
 * Compiled fragments deny by default: a condition that can never hold is
 * `1=0`, and so is an empty `or`. Columns are qualified with the resource's
 * table name, and relation lookups become `EXISTS` subqueries.
 *
 * Relation lookups for single-record checks that run at the same time are
 * batched into one query per relation table, such as checks over a page of
 * records with `Effect.forEach(records, check, { concurrency: "unbounded" })`.
 *
 * **Gotchas**
 *
 * `Condition.custom` conditions cannot be compiled. Compiling one is a defect,
 * so keep custom conditions off actions used to filter lists.
 *
 * **Example** (Filtering a list query)
 *
 * ```ts
 * class PermissionsSql extends PermissionSql.Service<PermissionsSql>()("app/PermissionsSql", {
 *   permissions: Permissions,
 *   tables: [PermissionSql.table(Unit, "units")],
 *   relations: [PermissionSql.relation(UnitMembership, { table: "profile_units", subject: "profile_id", object: "unit_id" })]
 * }) {}
 *
 * // In a repository built with `PermissionsSql.layer` available
 * const permissionsSql = yield* PermissionsSql
 * const visible = yield* permissionsSql.filter("units:read")
 * const units = yield* sql`SELECT * FROM units WHERE ${visible} ORDER BY name`
 * ```
 *
 * @stability experimental
 * @since 4.1.3
 */
import * as Context from "../Context.ts"
import * as Effect from "../Effect.ts"
import * as Exit from "../Exit.ts"
import * as Layer from "../Layer.ts"
import * as Request from "../Request.ts"
import * as RequestResolver from "../RequestResolver.ts"
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
        if (Condition.isRef(node.value)) return column(node.value)
        return sequence(node.value === true ? "1=1" : node.value === null || node.value === undefined ? "NULL" : "1=0")
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

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

interface Related extends Request.Request<boolean, PermissionError.PermissionUnavailable> {
  readonly mapping: RelationTable
  readonly subject: unknown
  readonly object: unknown
}

const Related = Request.of<Related>()

/**
 * The operations of a {@link Service}.
 *
 * **Details**
 *
 * - `filter` compiles the plan for an action into a fragment for the action's
 *   resource table. It needs only the principal and the authorizer, which the
 *   authorization middleware provides.
 * - `where` compiles any condition over a resource's fields.
 * - `related` looks up one relation fact in its table. Lookups that run at the
 *   same time share one query per relation table.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Shape<I, U extends Permission.Any> {
  readonly filter: <Ac extends Permission.ActionsOf<U>>(
    action: Ac
  ) => Effect.Effect<Statement.Fragment, PermissionError.PermissionUnavailable, I | Authorizer.Authorizer>
  readonly where: (condition: Condition.Condition<any>, resource: Schema.Top) => Effect.Effect<Statement.Fragment>
  readonly related: Authorizer.RelationStore["has"]
}

/**
 * Creates the operations of a {@link Service}, closing over the SQL client.
 *
 * **When to use**
 *
 * Use to build a service of your own instead of declaring one with
 * {@link Service}.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const make = <I, A, U extends Permission.Any>(
  permissions: Permission.Permissions<I, A, U>,
  options: {
    readonly tables: Iterable<Table<any>>
    readonly relations?: Iterable<RelationTable> | undefined
  }
): Effect.Effect<Shape<I, U>, never, SqlClient.SqlClient> =>
  Effect.gen(function*() {
    const sql = yield* SqlClient.SqlClient
    const tables = new Map(Array.from(options.tables, (mapping) => [mapping.resource, mapping] as const))
    const relations = new Map(Array.from(options.relations ?? [], (mapping) => [mapping.relation, mapping] as const))

    const tableFor = (resource: Schema.Top, label: string): Table => {
      const mapping = tables.get(resource)
      if (mapping === undefined) throw new Error(`PermissionSql: no table for the resource of ${label}`)
      return mapping
    }

    const where = (condition: Condition.Condition<any>, resource: Schema.Top) =>
      Effect.sync(() => compile(condition, tableFor(resource, "this condition"), relations))

    const filter = Effect.fnUntraced(function*(action: string) {
      const condition = yield* permissions.filter(action as Permission.ActionsOf<U>)
      const resource = permissions.actions.get(action)!.resource
      return yield* Effect.sync(() => compile(condition, tableFor(resource, `"${action}"`), relations))
    })

    // Lookups are batched by relation table and by transaction, so a lookup
    // inside a transaction still sees that transaction's writes
    const tableIds = new Map(Array.from(relations.values(), (mapping, index) => [mapping, index] as const))
    const connectionIds = new WeakMap<object, number>()
    let connections = 0
    const batchKey = (entry: Request.Entry<Related>): string => {
      const transaction = Context.getOrUndefined(entry.context as Context.Context<unknown>, sql.transactionService)
      if (transaction === undefined) return `${tableIds.get(entry.request.mapping)}`
      let connection = connectionIds.get(transaction[0])
      if (connection === undefined) {
        connection = connections++
        connectionIds.set(transaction[0], connection)
      }
      return `${tableIds.get(entry.request.mapping)}:${connection}`
    }

    // One query answers every lookup in the batch, each with the same
    // comparison a single lookup would use
    const resolver = RequestResolver.makeGrouped<Related, string>({
      key: batchKey,
      resolver: (entries) => {
        const { mapping } = entries[0].request
        const found = entries.map(({ request }, index) =>
          sql`CASE WHEN EXISTS (SELECT 1 FROM ${sql(mapping.table)} WHERE ${
            sql(mapping.subject)
          } = ${request.subject} AND ${sql(mapping.object)} = ${request.object}) THEN 1 ELSE 0 END AS ${
            sql(`found${index}`)
          }`
        )
        return sql<Record<string, unknown>>`SELECT ${sql.csv(found)}`.pipe(
          Effect.map(([row]) => {
            entries.forEach((entry, index) => entry.completeUnsafe(Exit.succeed(Number(row?.[`found${index}`]) === 1)))
          }),
          Effect.catchTag("SqlError", (error) =>
            Effect.logWarning(`Looking up relation "${mapping.relation.name}" failed`, error).pipe(
              Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
            ))
        )
      }
    }).pipe(RequestResolver.batchN(100))

    const related: Authorizer.RelationStore["has"] = (relation, subject, object) => {
      const mapping = relations.get(relation)
      if (mapping === undefined) {
        return Effect.logWarning(`No table is mapped for relation "${relation.name}"`).pipe(
          Effect.andThen(Effect.fail(new PermissionError.PermissionUnavailable()))
        )
      }
      return Effect.request(Related({ mapping, subject, object }), resolver)
    }

    return { filter, where, related } as Shape<I, U>
  })

/**
 * A service class created by {@link Service}.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type ServiceClass<Self, Id extends string, I, U extends Permission.Any> =
  & Context.ServiceClass<Self, Id, Shape<I, U>>
  & {
    /**
     * Provides the service, and the relation store the authorizer uses for
     * relation lookups. Requires a `SqlClient`.
     */
    readonly layer: Layer.Layer<Self, never, SqlClient.SqlClient>
  }

/**
 * Declares the application's SQL permission service for a `Permissions`
 * object and its table mappings.
 *
 * **Details**
 *
 * The service's `layer` closes over the SQL client and the mappings, so its
 * methods never require them. It also provides the relation store, so provide
 * it to the authorizer layer as well: `Permissions.layer.pipe(Layer.provideMerge(PermissionsSql.layer))`.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const Service = <Self>() =>
<const Id extends string, I, A, U extends Permission.Any>(
  id: Id,
  options: {
    readonly permissions: Permission.Permissions<I, A, U>
    readonly tables: Iterable<Table<any>>
    readonly relations?: Iterable<RelationTable> | undefined
  }
): ServiceClass<Self, Id, I, U> => {
  /** @effect-diagnostics-next-line classSelfMismatch:off */
  class PermissionSqlService extends Context.Service<Self, Shape<I, U>>()(id) {}
  const service = Layer.effect(PermissionSqlService, make(options.permissions, options))
  const store = Layer.effect(
    Authorizer.Relations,
    Effect.map(PermissionSqlService, (self): Authorizer.RelationStore => ({ has: self.related }))
  )
  return Object.assign(PermissionSqlService, {
    layer: store.pipe(Layer.provideMerge(service))
  }) as any
}
