import { assert, describe, it } from "@effect/vitest"
import { Effect, Exit } from "effect"
import { Condition } from "effect/permission"

interface Caller {
  readonly id: string
  readonly admin: boolean
  readonly hospitalId: string | undefined
  readonly unitIds: ReadonlyArray<string>
}

interface Doc {
  readonly id: string
  readonly ownerId: string
  readonly hospitalId: string | undefined
  readonly published: boolean
}

const { principal, resource } = Condition.refs<Caller, Doc>()
const Membership = Condition.relation<string, string>("member")

const caller: Caller = { id: "u1", admin: false, hospitalId: "h1", unitIds: ["d1", "d2"] }
const doc: Doc = { id: "d1", ownerId: "u1", hospitalId: "h1", published: false }

const evaluate = (
  condition: Condition.Condition<any>,
  overrides: { caller?: Partial<Caller>; doc?: Partial<Doc> } = {}
) =>
  Condition.evaluate(condition, {
    principal: { ...caller, ...overrides.caller },
    resource: { ...doc, ...overrides.doc },
    related: (_relation, subject, object) => Effect.succeed(subject === "u1" && object === "d1")
  })

describe("Condition", () => {
  describe("evaluate", () => {
    it.effect("compares fields of the principal and the resource", () =>
      Effect.gen(function*() {
        const isOwner = Condition.eq(resource.ownerId, principal.id)
        assert.isTrue(yield* evaluate(isOwner))
        assert.isFalse(yield* evaluate(isOwner, { doc: { ownerId: "u2" } }))
      }))

    it.effect("treats a boolean reference as a condition", () =>
      Effect.gen(function*() {
        const condition = Condition.or(principal.admin, resource.published)
        assert.isFalse(yield* evaluate(condition))
        assert.isTrue(yield* evaluate(condition, { doc: { published: true } }))
      }))

    it.effect("uses SQL three-valued logic for missing values", () =>
      Effect.gen(function*() {
        const sameHospital = Condition.eq(resource.hospitalId, principal.hospitalId)
        assert.isFalse(
          yield* evaluate(sameHospital, { caller: { hospitalId: undefined }, doc: { hospitalId: undefined } })
        )
        // not(unknown) stays unknown, so a missing value never passes by negation
        assert.isFalse(yield* evaluate(Condition.not(sameHospital), { caller: { hospitalId: undefined } }))
        assert.isTrue(yield* evaluate(Condition.isNull(principal.hospitalId), { caller: { hospitalId: undefined } }))
      }))

    it.effect("checks oneOf against literal lists and list fields", () =>
      Effect.gen(function*() {
        assert.isTrue(yield* evaluate(Condition.oneOf(resource.id, principal.unitIds)))
        assert.isFalse(yield* evaluate(Condition.oneOf(resource.id, ["d3", "d4"])))
        assert.isFalse(yield* evaluate(Condition.oneOf(resource.id, [])))
      }))

    it.effect("looks up relations", () =>
      Effect.gen(function*() {
        const isMember = Condition.related(Membership, principal.id, resource.id)
        assert.isTrue(yield* evaluate(isMember))
        assert.isFalse(yield* evaluate(isMember, { doc: { id: "d2" } }))
      }))

    it.effect("runs custom conditions last and stops early", () =>
      Effect.gen(function*() {
        let runs = 0
        const expensive = Condition.custom("expensive", () => Effect.sync(() => (runs++, true)))
        assert.isFalse(yield* evaluate(Condition.and(expensive, Condition.eq(resource.ownerId, "nobody"))))
        assert.strictEqual(runs, 0)
        assert.isTrue(yield* evaluate(Condition.and(expensive, Condition.eq(resource.ownerId, "u1"))))
        assert.strictEqual(runs, 1)
      }))

    it.effect("reports custom failures as CustomConditionError", () =>
      Effect.gen(function*() {
        const exit = yield* Effect.exit(evaluate(Condition.custom("broken", () => Effect.fail("boom"))))
        assert.isTrue(Exit.isFailure(exit))
        const error = yield* Effect.flip(evaluate(Condition.custom("broken", () => Effect.fail("boom"))))
        assert.strictEqual(error._tag, "CustomConditionError")
        assert.strictEqual(error.name, "broken")
      }))
  })

  describe("simplify", () => {
    it("fills in the principal and leaves resource fields", () => {
      const simplified = Condition.simplify(
        Condition.and(Condition.not(principal.admin), Condition.eq(resource.ownerId, principal.id)),
        caller
      )
      assert.strictEqual(simplified._tag, "Compare")
      if (simplified._tag === "Compare") {
        assert.isTrue(Condition.isRef(simplified.left))
        assert.strictEqual(simplified.right, "u1")
      }
    })

    it("folds conditions that become known", () => {
      assert.isTrue(
        Condition.isAlways(Condition.simplify(Condition.or(principal.admin, resource.published), { admin: true }))
      )
      assert.isTrue(
        Condition.isNever(Condition.simplify(Condition.and(principal.admin, resource.published), { admin: false }))
      )
      assert.isTrue(Condition.isNever(Condition.simplify(Condition.or(), caller)))
      assert.isTrue(Condition.isAlways(Condition.simplify(Condition.and(), caller)))
    })

    it("turns a principal list into a literal list", () => {
      const simplified = Condition.simplify(Condition.oneOf(resource.id, principal.unitIds), caller)
      assert.strictEqual(simplified._tag, "OneOf")
      assert.isTrue(
        Condition.isNever(Condition.simplify(Condition.oneOf(resource.id, principal.unitIds), { unitIds: [] }))
      )
    })

    it("keeps a missing principal value unknown, so negation does not pass", () => {
      const simplified = Condition.simplify(
        Condition.not(Condition.eq(resource.hospitalId, principal.hospitalId)),
        { ...caller, hospitalId: undefined }
      )
      assert.isTrue(Condition.isNever(simplified))
    })
  })
})
