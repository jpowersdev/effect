/**
 * Conditions are the inspectable expressions permission rules are written in.
 *
 * A condition is data, not a function: `Condition.eq(unit.hospitalId,
 * principal.attributes.homeHospitalId)` records which fields are compared
 * instead of comparing them. That is what lets the same condition be checked
 * against one record in memory, simplified once the principal is known, and
 * compiled into a SQL `WHERE` clause by `PermissionSql`.
 *
 * Fields are referenced through {@link Refs}, typed views of the principal and
 * the resource whose properties are references rather than values.
 *
 * **Details**
 *
 * Conditions use SQL's three-valued logic so that in-memory checks and compiled
 * filters agree: comparing a missing (`null` or `undefined`) value is unknown,
 * `not` of unknown is unknown, and a condition that ends up unknown does not
 * pass.
 *
 * **Gotchas**
 *
 * - {@link custom} conditions run arbitrary effects. They work for checks on a
 *   single record, but cannot be compiled to SQL.
 * - References are proxies: any property name except `then` and `toJSON` reads
 *   as a nested field.
 *
 * @stability experimental
 * @since 4.1.3
 */
import type * as Brand from "../Brand.ts"
import * as Data from "../Data.ts"
import * as Effect from "../Effect.ts"
import * as Predicate from "../Predicate.ts"
import type * as Types from "../Types.ts"

const TypeId = "~effect/permission/Condition" as const
const RefTypeId = "~effect/permission/Condition/Ref" as const
const RelationTypeId = "~effect/permission/Condition/Relation" as const

// -----------------------------------------------------------------------------
// References
// -----------------------------------------------------------------------------

/**
 * Where a reference points: the principal making the request, or the resource
 * being accessed.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Source = "principal" | "resource"

/**
 * A reference to a field of the principal or the resource, used as an operand
 * in a condition instead of a value.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Ref<out A> {
  readonly [RefTypeId]: {
    readonly _A: Types.Covariant<A>
    readonly source: Source
    readonly path: ReadonlyArray<string>
  }
}

type Leaf =
  | string
  | number
  | boolean
  | bigint
  | symbol
  | null
  | undefined
  | Date
  | ReadonlyArray<any>
  | ReadonlySet<any>
  | ReadonlyMap<any, any>
  | ((...args: ReadonlyArray<any>) => any)

/**
 * A typed view of a value whose fields are {@link Ref}s instead of values.
 *
 * **Details**
 *
 * Objects expose one reference per field, recursively. Primitives, arrays,
 * sets, maps, dates, and functions are leaves.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Refs<A> = [NonNullable<A>] extends [Leaf] ? Ref<A>
  : [NonNullable<A>] extends [object] ?
      & Ref<A>
      & {
        readonly [K in keyof NonNullable<A> & string]: Refs<NonNullable<A>[K] | Extract<A, null | undefined>>
      }
  : Ref<A>

/**
 * A condition operand: either a literal value or a {@link Ref} to a field.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Operand<A> = A | Ref<A>

type Unbrand<A> = A extends Brand.Brand<any> ? Brand.Brand.Unbranded<A> : A

/**
 * Returns `true` when a value is a {@link Ref}.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isRef = (u: unknown): u is Ref<unknown> => Predicate.hasProperty(u, RefTypeId)

const refMeta = (ref: Ref<unknown>): { readonly source: Source; readonly path: ReadonlyArray<string> } => ref[RefTypeId]

const makeRef = (source: Source, path: ReadonlyArray<string>): any => {
  const meta = { source, path }
  return new Proxy({ [RefTypeId]: meta }, {
    get(_target, key) {
      if (key === RefTypeId) return meta
      if (typeof key === "symbol" || key === "then") return undefined
      if (key === "toJSON") return () => ({ _id: "Ref", source, path })
      return makeRef(source, [...path, key])
    }
  })
}

/**
 * Creates root references for writing conditions outside `Permission.rules`.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const refs = <Principal, Resource>(): {
  readonly principal: Refs<Principal>
  readonly resource: Refs<Resource>
} => ({ principal: makeRef("principal", []), resource: makeRef("resource", []) })

// -----------------------------------------------------------------------------
// Relations
// -----------------------------------------------------------------------------

/**
 * A named relationship between a subject and an object, such as "profile is a
 * member of unit".
 *
 * **Details**
 *
 * A relation says nothing about where its facts are stored. The relation store
 * provided to the authorizer answers lookups, for example from a SQL table via
 * `PermissionSql.relation`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Relation<in out Subject, in out Object> {
  readonly [RelationTypeId]: {
    readonly _Subject: Types.Invariant<Subject>
    readonly _Object: Types.Invariant<Object>
  }
  readonly name: string
  /**
   * Creates one fact of this relation, for in-memory relation stores and
   * tests.
   */
  of(subject: Subject, object: Object): RelationTuple
}

/**
 * One fact of a {@link Relation}: this subject is related to this object.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface RelationTuple {
  readonly relation: Relation<any, any>
  readonly subject: unknown
  readonly object: unknown
}

/**
 * Declares a relation between subjects and objects.
 *
 * **Example** (Declaring a membership relation)
 *
 * ```ts
 * import { Condition } from "effect/permission"
 *
 * const UnitMembership = Condition.relation<string, string>("unit:member")
 * ```
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const relation = <Subject, Object>(name: string): Relation<Subject, Object> => {
  const self: Relation<Subject, Object> = {
    [RelationTypeId]: { _Subject: (_) => _, _Object: (_) => _ },
    name,
    of: (subject, object) => ({ relation: self, subject, object })
  }
  return self
}

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

interface Proto<R> {
  readonly [TypeId]: {
    readonly _R: Types.Covariant<R>
  }
}

/**
 * A condition that is always true, always false, or unknown (`null`).
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Literal extends Proto<never> {
  readonly _tag: "Literal"
  readonly value: boolean | null
}

/**
 * A condition that holds when a boolean field is `true`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Truthy extends Proto<never> {
  readonly _tag: "Truthy"
  readonly value: Operand<unknown>
}

/**
 * Comparison operators supported by {@link Compare}.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Operator = "eq" | "neq" | "lt" | "lte" | "gt" | "gte"

/**
 * A condition that compares two operands.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Compare extends Proto<never> {
  readonly _tag: "Compare"
  readonly operator: Operator
  readonly left: Operand<unknown>
  readonly right: Operand<unknown>
}

/**
 * A condition that holds when a value is one of a list of values.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface OneOf extends Proto<never> {
  readonly _tag: "OneOf"
  readonly value: Operand<unknown>
  readonly list: ReadonlyArray<Operand<unknown>> | Ref<unknown>
}

/**
 * A condition that holds when a value is `null` or `undefined`.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface IsNull extends Proto<never> {
  readonly _tag: "IsNull"
  readonly value: Operand<unknown>
}

/**
 * A condition that holds when every condition holds.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface And<R> extends Proto<R> {
  readonly _tag: "And"
  readonly conditions: ReadonlyArray<Condition<R>>
}

/**
 * A condition that holds when at least one condition holds.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Or<R> extends Proto<R> {
  readonly _tag: "Or"
  readonly conditions: ReadonlyArray<Condition<R>>
}

/**
 * A condition that holds when another condition is false.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Not<R> extends Proto<R> {
  readonly _tag: "Not"
  readonly condition: Condition<R>
}

/**
 * A condition that holds when a {@link Relation} fact exists between a subject
 * and an object.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Related extends Proto<never> {
  readonly _tag: "Related"
  readonly relation: Relation<any, any>
  readonly subject: Operand<unknown>
  readonly object: Operand<unknown>
}

/**
 * A condition that runs an effect against the real principal and resource.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export interface Custom<R> extends Proto<R> {
  readonly _tag: "Custom"
  readonly name: string
  readonly evaluate: (input: {
    readonly principal: any
    readonly resource: any
  }) => Effect.Effect<boolean, unknown, R>
}

/**
 * An inspectable condition over the principal and the resource. `R` is the
 * services required by any {@link custom} conditions it contains.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Condition<R = never> =
  | Literal
  | Truthy
  | Compare
  | OneOf
  | IsNull
  | And<R>
  | Or<R>
  | Not<R>
  | Related
  | Custom<R>

/**
 * A value accepted wherever a condition is expected: a condition, or a
 * reference to a boolean field.
 *
 * @stability experimental
 * @category models
 * @since 4.1.3
 */
export type Input<R = never> = Condition<R> | Ref<boolean> | Ref<boolean | null | undefined>

/**
 * Extracts the services required by a condition.
 *
 * @stability experimental
 * @category utility types
 * @since 4.1.3
 */
export type Services<C> = C extends { readonly [TypeId]: { readonly _R: Types.Covariant<infer R> } } ? R : never

/**
 * Returns `true` when a value is a {@link Condition}.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isCondition = (u: unknown): u is Condition<unknown> => Predicate.hasProperty(u, TypeId)

const variance = { _R: (_: never) => _ }

const make = <C extends Condition<any>>(node: Omit<C, typeof TypeId>): C => ({ [TypeId]: variance, ...node }) as C

const normalize = <R>(input: Input<R>): Condition<R> =>
  isRef(input) ? make<Truthy>({ _tag: "Truthy", value: input }) : input

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * A condition that always holds.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const always: Condition = make<Literal>({ _tag: "Literal", value: true })

/**
 * A condition that never holds.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const never: Condition = make<Literal>({ _tag: "Literal", value: false })

const unknown: Condition = make<Literal>({ _tag: "Literal", value: null })

const literal = (value: boolean | null): Condition => value === true ? always : value === false ? never : unknown

const compare = (operator: Operator) => (left: Operand<unknown>, right: Operand<unknown>): Condition =>
  make<Compare>({ _tag: "Compare", operator, left, right })

/**
 * Creates a condition that holds when two operands are equal.
 *
 * **Example** (Matching the owner)
 *
 * ```ts
 * import { Condition } from "effect/permission"
 *
 * const { principal, resource } = Condition.refs<{ readonly id: string }, { readonly ownerId: string }>()
 * const isOwner = Condition.eq(resource.ownerId, principal.id)
 * ```
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const eq: <A>(left: Operand<A>, right: Operand<Unbrand<NoInfer<A>>>) => Condition = compare("eq")

/**
 * Creates a condition that holds when two operands are not equal.
 *
 * **Gotchas**
 *
 * Like SQL `<>`, comparing a missing value is unknown, not true.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const notEq: <A>(left: Operand<A>, right: Operand<Unbrand<NoInfer<A>>>) => Condition = compare("neq")

/**
 * Creates a condition that holds when the left operand is less than the right.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const lt: <A>(left: Operand<A>, right: Operand<Unbrand<NoInfer<A>>>) => Condition = compare("lt")

/**
 * Creates a condition that holds when the left operand is less than or equal
 * to the right.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const lte: <A>(left: Operand<A>, right: Operand<Unbrand<NoInfer<A>>>) => Condition = compare("lte")

/**
 * Creates a condition that holds when the left operand is greater than the
 * right.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const gt: <A>(left: Operand<A>, right: Operand<Unbrand<NoInfer<A>>>) => Condition = compare("gt")

/**
 * Creates a condition that holds when the left operand is greater than or
 * equal to the right.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const gte: <A>(left: Operand<A>, right: Operand<Unbrand<NoInfer<A>>>) => Condition = compare("gte")

/**
 * Creates a condition that holds when a value is one of a list of values. The
 * list can be literal operands or a reference to an array or set field.
 *
 * **Gotchas**
 *
 * `null` and `undefined` entries in the list are ignored.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const oneOf = <A>(
  value: Operand<A>,
  list:
    | ReadonlyArray<Operand<Unbrand<NoInfer<A>>>>
    | Ref<ReadonlyArray<Unbrand<NoInfer<A>>> | ReadonlySet<Unbrand<NoInfer<A>>> | null | undefined>
): Condition => make<OneOf>({ _tag: "OneOf", value, list: list as OneOf["list"] })

/**
 * Creates a condition that holds when a value is `null` or `undefined`.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const isNull = (value: Operand<unknown>): Condition => make<IsNull>({ _tag: "IsNull", value })

/**
 * Creates a condition that holds when a value is neither `null` nor
 * `undefined`.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const isNotNull = (value: Operand<unknown>): Condition => not(isNull(value))

/**
 * Creates a condition that holds when every input holds. With no inputs it
 * always holds.
 *
 * @stability experimental
 * @category combinators
 * @since 4.1.3
 */
export const and = <const Inputs extends ReadonlyArray<Input<any>>>(
  ...inputs: Inputs
): Condition<Services<Inputs[number]>> => make<And<any>>({ _tag: "And", conditions: inputs.map(normalize) })

/**
 * Creates a condition that holds when at least one input holds. With no inputs
 * it never holds.
 *
 * @stability experimental
 * @category combinators
 * @since 4.1.3
 */
export const or = <const Inputs extends ReadonlyArray<Input<any>>>(
  ...inputs: Inputs
): Condition<Services<Inputs[number]>> => make<Or<any>>({ _tag: "Or", conditions: inputs.map(normalize) })

/**
 * Creates a condition that holds when the input is false.
 *
 * **Gotchas**
 *
 * Like SQL `NOT`, negating an unknown result is still unknown.
 *
 * @stability experimental
 * @category combinators
 * @since 4.1.3
 */
export const not = <R>(input: Input<R>): Condition<R> => make<Not<R>>({ _tag: "Not", condition: normalize(input) })

/**
 * Creates a condition that holds when a relation fact exists between a subject
 * and an object.
 *
 * **Example** (Checking unit membership)
 *
 * ```ts
 * import { Condition } from "effect/permission"
 *
 * const UnitMembership = Condition.relation<string, string>("unit:member")
 * const { principal, resource } = Condition.refs<{ readonly id: string }, { readonly unitId: string }>()
 *
 * const isMember = Condition.related(UnitMembership, principal.id, resource.unitId)
 * ```
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const related = <Subject, Object>(
  relation: Relation<Subject, Object>,
  subject: Operand<Unbrand<NoInfer<Subject>>>,
  object: Operand<Unbrand<NoInfer<Object>>>
): Condition => make<Related>({ _tag: "Related", relation, subject, object })

/**
 * Creates a condition from an effect that receives the real principal and
 * resource values.
 *
 * **When to use**
 *
 * Use when a rule cannot be expressed as data, such as a check that calls
 * another service.
 *
 * **Gotchas**
 *
 * - Custom conditions cannot be compiled to SQL, so avoid them on actions
 *   used to filter lists.
 * - A failure becomes a `CustomConditionError`, never an allow or a deny.
 *
 * @stability experimental
 * @category constructors
 * @since 4.1.3
 */
export const custom = <Principal = any, Resource = any, R = never>(
  name: string,
  evaluate: (
    input: { readonly principal: Principal; readonly resource: Resource }
  ) => Effect.Effect<boolean, unknown, R>
): Condition<R> => make<Custom<R>>({ _tag: "Custom", name, evaluate })

// -----------------------------------------------------------------------------
// Inspection
// -----------------------------------------------------------------------------

/**
 * Returns `true` when a condition is the literal {@link always}.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isAlways = (self: Condition<any>): boolean => self._tag === "Literal" && self.value === true

/**
 * Returns `true` when a condition can never hold: it is the literal
 * {@link never} or the unknown literal.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const isNever = (self: Condition<any>): boolean => self._tag === "Literal" && self.value !== true

/**
 * Returns `true` when a condition contains a {@link custom} condition.
 *
 * @stability experimental
 * @category guards
 * @since 4.1.3
 */
export const hasCustom = (self: Condition<any>): boolean => {
  switch (self._tag) {
    case "Custom":
      return true
    case "And":
    case "Or":
      return self.conditions.some(hasCustom)
    case "Not":
      return hasCustom(self.condition)
    default:
      return false
  }
}

// -----------------------------------------------------------------------------
// Evaluation
// -----------------------------------------------------------------------------

type Truth = boolean | null

const getPath = (root: unknown, path: ReadonlyArray<string>): unknown => {
  let current = root
  for (const key of path) {
    if (current === null || current === undefined) return undefined
    current = (current as Record<string, unknown>)[key]
  }
  return current
}

const isMissing = (u: unknown): u is null | undefined => u === null || u === undefined

const compareValues = (operator: Operator, left: unknown, right: unknown): Truth => {
  if (isMissing(left) || isMissing(right)) return null
  const l = left instanceof Date ? left.getTime() : left
  const r = right instanceof Date ? right.getTime() : right
  switch (operator) {
    case "eq":
      return l === r
    case "neq":
      return l !== r
    case "lt":
      return (l as any) < (r as any)
    case "lte":
      return (l as any) <= (r as any)
    case "gt":
      return (l as any) > (r as any)
    case "gte":
      return (l as any) >= (r as any)
  }
}

const toList = (value: unknown): ReadonlyArray<unknown> | undefined =>
  Array.isArray(value) ? value : value instanceof Set ? Array.from(value) : undefined

const oneOfValues = (value: unknown, list: ReadonlyArray<unknown> | undefined): Truth => {
  if (isMissing(value) || list === undefined) return null
  return list.some((item) => !isMissing(item) && compareValues("eq", value, item) === true)
}

const truthyValue = (value: unknown): Truth => value === true ? true : isMissing(value) ? null : false

const andTruth = (values: ReadonlyArray<Truth>): Truth =>
  values.some((value) => value === false) ? false : values.some((value) => value === null) ? null : true

const orTruth = (values: ReadonlyArray<Truth>): Truth =>
  values.some((value) => value === true) ? true : values.some((value) => value === null) ? null : false

const cost = (self: Condition<any>): number => {
  switch (self._tag) {
    case "Custom":
      return 2
    case "Related":
      return 1
    case "And":
    case "Or":
      return Math.max(0, ...self.conditions.map(cost))
    case "Not":
      return cost(self.condition)
    default:
      return 0
  }
}

const byCost = (conditions: ReadonlyArray<Condition<any>>): ReadonlyArray<Condition<any>> =>
  conditions.map((condition, index) => ({ condition, index, cost: cost(condition) }))
    .sort((a, b) => a.cost - b.cost || a.index - b.index)
    .map(({ condition }) => condition)

/**
 * The failure of a {@link custom} condition's effect.
 *
 * @stability experimental
 * @category errors
 * @since 4.1.3
 */
export class CustomConditionError extends Data.TaggedError("CustomConditionError")<{
  readonly name: string
  readonly cause: unknown
}> {}

/**
 * Evaluates a condition against a real principal and resource.
 *
 * **Details**
 *
 * Inexpensive comparisons run first, then relation lookups, then custom
 * conditions, stopping as soon as the result is known. Relation lookups go
 * through `related`; evaluating a relation without it is a defect.
 *
 * @stability experimental
 * @category evaluation
 * @since 4.1.3
 */
export const evaluate = <R, E = never, R2 = never>(
  self: Condition<R>,
  options: {
    readonly principal: unknown
    readonly resource: unknown
    readonly related?:
      | ((relation: Relation<any, any>, subject: unknown, object: unknown) => Effect.Effect<boolean, E, R2>)
      | undefined
  }
): Effect.Effect<boolean, E | CustomConditionError, R | R2> => {
  const resolve = (operand: Operand<unknown>): unknown => {
    if (!isRef(operand)) return operand
    const { path, source } = refMeta(operand)
    return getPath(source === "principal" ? options.principal : options.resource, path)
  }
  const go = (condition: Condition<any>): Effect.Effect<Truth, E | CustomConditionError, R | R2> => {
    switch (condition._tag) {
      case "Literal":
        return Effect.succeed(condition.value)
      case "Truthy":
        return Effect.succeed(truthyValue(resolve(condition.value)))
      case "Compare":
        return Effect.succeed(compareValues(condition.operator, resolve(condition.left), resolve(condition.right)))
      case "OneOf":
        return Effect.succeed(oneOfValues(
          resolve(condition.value),
          isRef(condition.list) ? toList(resolve(condition.list)) : condition.list.map(resolve)
        ))
      case "IsNull":
        return Effect.succeed(isMissing(resolve(condition.value)))
      case "Not":
        return Effect.map(go(condition.condition), (value) => value === null ? null : !value)
      case "And":
      case "Or": {
        const stop = condition._tag !== "And"
        const combine = condition._tag === "And" ? andTruth : orTruth
        return Effect.suspend(() => {
          const results: Array<Truth> = []
          const conditions = byCost(condition.conditions)
          const loop = (index: number): Effect.Effect<Truth, E | CustomConditionError, R | R2> =>
            index === conditions.length ?
              Effect.succeed(combine(results)) :
              Effect.flatMap(go(conditions[index]), (value) => {
                if (value === stop) return Effect.succeed(stop)
                results.push(value)
                return loop(index + 1)
              })
          return loop(0)
        })
      }
      case "Related": {
        const subject = resolve(condition.subject)
        const object = resolve(condition.object)
        if (isMissing(subject) || isMissing(object)) return Effect.succeed(null)
        if (options.related === undefined) {
          return Effect.die(new Error(`Condition.evaluate: no relation lookup for "${condition.relation.name}"`))
        }
        return options.related(condition.relation, subject, object)
      }
      case "Custom":
        return condition.evaluate({ principal: options.principal, resource: options.resource }).pipe(
          Effect.mapError((cause) => new CustomConditionError({ name: condition.name, cause }))
        )
    }
  }
  return Effect.map(go(self), (value) => value === true)
}

/**
 * Substitutes the principal's values into a condition and folds whatever
 * becomes known, leaving a condition over resource fields only.
 *
 * **When to use**
 *
 * Use to prepare a condition for compiling to SQL, or to ask whether a
 * principal could ever pass: a result of {@link never} means no resource
 * qualifies.
 *
 * **Details**
 *
 * Relation lookups and custom conditions are kept as they are, with the
 * principal's values filled in.
 *
 * @stability experimental
 * @category evaluation
 * @since 4.1.3
 */
export const simplify = <R>(self: Condition<R>, principal: unknown): Condition<R> => {
  const substitute = (operand: Operand<unknown>): Operand<unknown> => {
    if (!isRef(operand)) return operand
    const { path, source } = refMeta(operand)
    return source === "principal" ? getPath(principal, path) : operand
  }
  const go = (condition: Condition<any>): Condition<any> => {
    switch (condition._tag) {
      case "Literal":
      case "Custom":
        return condition
      case "Truthy": {
        const value = substitute(condition.value)
        return isRef(value) ? condition : literal(truthyValue(value))
      }
      case "Compare": {
        const left = substitute(condition.left)
        const right = substitute(condition.right)
        if (!isRef(left) && !isRef(right)) return literal(compareValues(condition.operator, left, right))
        if ((!isRef(left) && isMissing(left)) || (!isRef(right) && isMissing(right))) return unknown
        return make<Compare>({ _tag: "Compare", operator: condition.operator, left, right })
      }
      case "OneOf": {
        const value = substitute(condition.value)
        const listOperand = isRef(condition.list) ? substitute(condition.list) : condition.list.map(substitute)
        const list = isRef(listOperand) ? listOperand : toList(listOperand)
        if (!isRef(value) && isMissing(value)) return unknown
        if (list === undefined) return unknown
        if (isRef(list)) return make<OneOf>({ _tag: "OneOf", value, list })
        const known = list.filter((item) => !isRef(item))
        const pending = list.filter(isRef)
        if (!isRef(value) && pending.length === 0) return literal(oneOfValues(value, known))
        if (isRef(value) && pending.length === 0 && known.every(isMissing)) return never
        return make<OneOf>({ _tag: "OneOf", value, list })
      }
      case "IsNull": {
        const value = substitute(condition.value)
        return isRef(value) ? make<IsNull>({ _tag: "IsNull", value }) : literal(isMissing(value))
      }
      case "Not": {
        const inner = go(condition.condition)
        return inner._tag === "Literal" ? literal(inner.value === null ? null : !inner.value) : not(inner)
      }
      case "And":
      case "Or": {
        const isAnd = condition._tag === "And"
        const parts: Array<Condition<any>> = []
        for (const child of condition.conditions) {
          const simplified = go(child)
          if (simplified._tag === condition._tag) {
            parts.push(...simplified.conditions)
          } else {
            parts.push(simplified)
          }
        }
        if (parts.some((part) => part._tag === "Literal" && part.value === !isAnd)) return isAnd ? never : always
        const rest = parts.filter((part) => !(part._tag === "Literal" && part.value === isAnd))
        if (rest.length === 0) return isAnd ? always : never
        if (rest.length === 1) return rest[0]
        return isAnd ? and(...rest) : or(...rest)
      }
      case "Related":
        return make<Related>({
          _tag: "Related",
          relation: condition.relation,
          subject: substitute(condition.subject),
          object: substitute(condition.object)
        })
    }
  }
  return go(self)
}

/** @internal */
export const refPath = (ref: Ref<unknown>): { readonly source: Source; readonly path: ReadonlyArray<string> } =>
  refMeta(ref)
