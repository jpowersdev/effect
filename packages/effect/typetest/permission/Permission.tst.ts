import { Clock, Context, Effect, type Layer, Schema } from "effect"
import { type Authorizer, Condition, Permission, type PermissionError, Principal } from "effect/permission"
import { Model } from "effect/schema"
import { describe, expect, it } from "tstyche"

const ProfileId = Schema.String.pipe(Schema.brand("ProfileId"))
type ProfileId = typeof ProfileId.Type

class Post extends Model.Class<Post>("Post")({
  id: Model.GeneratedByDb(Schema.Number),
  authorId: Model.GeneratedByApp(ProfileId),
  status: Model.GeneratedByApp(Schema.Literals(["draft", "live"])),
  title: Schema.String,
  createdAt: Model.DateTimeInsert,
  updatedAt: Model.DateTimeUpdate
}) {}

class Note extends Schema.Class<Note>("Note")({
  id: Schema.String,
  authorId: Schema.String,
  body: Schema.String
}) {}

interface Member {
  readonly editor: boolean
}

class CurrentPrincipal extends Context.Service<
  CurrentPrincipal,
  Principal.Principal<Member, ProfileId>
>()("test/CurrentPrincipal") {}

interface LazyMember {
  readonly editor: boolean
  readonly teamIds: Principal.Lazy<ReadonlyArray<string>>
}

class LazyPrincipal extends Context.Service<
  LazyPrincipal,
  Principal.Principal<LazyMember, ProfileId>
>()("test/LazyPrincipal") {}

class UntypedPrincipal extends Context.Service<
  UntypedPrincipal,
  Principal.Principal<Member>
>()("test/UntypedPrincipal") {}

const PostRules = Permission.rules(CurrentPrincipal, Post)
  .action("posts:read", { filter: ({ resource: post }) => Condition.eq(post.status, "live") })
  .action("posts:update", {
    filter: ({ principal, resource: post, allowed }) =>
      Condition.and(allowed("posts:read"), Condition.eq(post.authorId, principal.subject.id))
  })
  .create("posts:create", {
    check: ({ principal }) => principal.attributes.editor,
    set: ({ principal }) => ({ authorId: principal.subject.id, status: "draft" })
  })
  .action("posts:approve", {
    filter: ({ principal }) => principal.attributes.editor,
    set: () => ({ status: "live" })
  })

const NoteRules = Permission.rules(CurrentPrincipal, Note)
  .create("notes:create", { check: () => Condition.always })
  .action("notes:edit", {
    filter: ({ principal, resource: note }) => Condition.eq(note.authorId, principal.subject.id)
  })

const Permissions = Permission.make(CurrentPrincipal, { rules: [PostRules, NoteRules] })

declare const post: Post
declare const note: Note
declare const payload: typeof Post.jsonCreate.Type

describe("Principal", () => {
  it("keeps a branded subject id and widens any other", () => {
    expect(Principal.make({ subject: "p-1", attributes: {} })).type.toBe<Principal.Authenticated<{}, string>>()
    expect(Principal.make({ subject: ProfileId.make("p-1"), attributes: {} })).type.toBe<
      Principal.Authenticated<{}, ProfileId>
    >()
  })
})

describe("lazy attributes", () => {
  it("are effects of the value they load", () => {
    expect(Principal.lazy(Effect.succeed(1))).type.toBe<Principal.Lazy<number>>()
    expect(Effect.gen(function*() {
      return yield* Principal.lazy(Effect.fail("down").pipe(Effect.as(1)))
    })).type.toBe<Effect.Effect<number, PermissionError.PermissionUnavailable>>()
    expect(
      Principal.make({
        subject: ProfileId.make("p-1"),
        attributes: { editor: true, teamIds: Principal.lazy(Effect.succeed([])) }
      })
    )
      .type.toBeAssignableTo<Principal.Principal<LazyMember, ProfileId>>()
  })

  it("can't require services", () => {
    // @ts-expect-error Type 'CurrentPrincipal' is not assignable to type 'never'
    // @effect-diagnostics-next-line missingEffectContext:off
    Principal.lazy(Effect.as(CurrentPrincipal, []))
  })

  it("must be wrapped, so an effect is never read as a value", () => {
    Principal.make({
      subject: "p-1",
      // @ts-expect-error Property '"is an effect, so wrap it with Principal.lazy"' is missing
      attributes: { teamIds: Effect.succeed([]) }
    })
    Principal.make({
      subject: "p-1",
      // @ts-expect-error Property '"is an effect, so wrap it with Principal.lazy"' is missing
      attributes: Effect.succeed({ editor: true })
    })
  })

  it("can be the whole attributes object", () => {
    const principal = Principal.make({
      subject: ProfileId.make("p-1"),
      attributes: Principal.lazy(
        Effect.all({ editor: Effect.succeed(true), teamIds: Effect.succeed<ReadonlyArray<string>>([]) })
      )
    })
    expect(principal).type.toBeAssignableTo<Principal.Principal<Principal.Lazy<Member>, ProfileId>>()
    class WholeLazyPrincipal extends Context.Service<
      WholeLazyPrincipal,
      Principal.Principal<Principal.Lazy<Member>, ProfileId>
    >()("test/WholeLazyPrincipal") {}
    // Rules refer to its fields as usual
    Permission.rules(WholeLazyPrincipal, Note).action("notes:edit", {
      filter: ({ principal }) => principal.attributes.editor
    })
  })

  it("are referred to in rules as the value they load", () => {
    Permission.rules(LazyPrincipal, Note).action("notes:team", {
      filter: ({ principal, resource: note }) => Condition.oneOf(note.authorId, principal.attributes.teamIds)
    })
    Permission.rules(LazyPrincipal, Note).action("notes:mine", {
      // @ts-expect-error Argument of type 'Ref<readonly string[]>' is not assignable to parameter of type 'Operand<string>'
      filter: ({ principal, resource: note }) => Condition.eq(note.authorId, principal.attributes.teamIds)
    })
  })

  it("are read in set with an effect", () => {
    const Rules = Permission.rules(LazyPrincipal, Note).create("notes:create", {
      check: () => Condition.always,
      set: ({ principal }) => Effect.map(principal.attributes.teamIds, (teamIds) => ({ body: teamIds.join() }))
    })
    expect<Permission.PayloadOf<typeof Rules, "notes:create">>().type.toBe<
      | { readonly id: string; readonly authorId: string; readonly body?: never }
      | { readonly id: string; readonly authorId: string; readonly body: string }
    >()
    Permission.rules(LazyPrincipal, Note).create("notes:create", {
      check: () => Condition.always,
      // @ts-expect-error Type 'Lazy<readonly string[]>' is not assignable to type 'string'
      set: ({ principal }) => ({ body: principal.attributes.teamIds })
    })
  })
})

describe("rules", () => {
  it("types set with the principal's id", () => {
    Permission.rules(UntypedPrincipal, Post).create("posts:create", {
      check: () => Condition.always,
      // @ts-expect-error Type 'string' is not assignable to type 'string & Brand<"ProfileId">'
      set: ({ principal }) => ({ authorId: principal.subject.id, status: "draft" })
    })
  })

  it("requires set to fill the fields the payload doesn't provide", () => {
    PostRules.create("posts:publish", {
      check: () => Condition.always,
      // @ts-expect-error Property 'status' is missing in type '{ authorId: string & Brand<"ProfileId">; }' but required in type 'RequiredPresets<typeof Post>'
      set: ({ principal }) => ({ authorId: principal.subject.id })
    })
    // A resource that isn't a Model takes every field from the payload
    NoteRules.create("notes:import", { check: () => Condition.always })
  })

  it("types an action's set against the value update builds", () => {
    PostRules.action("posts:reassign", {
      filter: () => Condition.always,
      set: ({ principal }) => ({ authorId: principal.subject.id })
    })
    PostRules.action("posts:hide", {
      filter: () => Condition.always,
      // @ts-expect-error Type '"hidden"' is not assignable to type '"draft" | "live"'
      set: () => ({ status: "hidden" })
    })
  })

  it("types create rules against the value create builds", () => {
    PostRules.create("posts:publish", {
      // @ts-expect-error Property 'id' does not exist on type 'ObjectRefs<{ readonly authorId: string & Brand<"ProfileId">;
      check: ({ resource: post }) => Condition.eq(post.id, 1),
      set: ({ principal }) => ({ authorId: principal.subject.id, status: "live" })
    })
  })

  it("only lets allowed refer to actions on existing resources declared before", () => {
    PostRules.action("posts:delete", {
      // @ts-expect-error Argument of type '"posts:create"' is not assignable to parameter of type '"posts:read" | "posts:update" | "posts:approve"'
      filter: ({ allowed }) => allowed("posts:create")
    })
    Permission.rules(CurrentPrincipal, Post).action("posts:update", {
      // @ts-expect-error Argument of type '"posts:read"' is not assignable to parameter of type 'never'
      filter: ({ allowed }) => allowed("posts:read")
    })
  })

  it("rejects an action declared twice", () => {
    // @ts-expect-error Argument of type 'string' is not assignable to parameter of type 'AlreadyDeclared<"posts:read">'
    PostRules.action("posts:read", { filter: () => Condition.always })
    // @ts-expect-error Argument of type 'string' is not assignable to parameter of type 'AlreadyDeclared<"posts:create">'
    PostRules.create("posts:create", {
      check: () => Condition.always,
      set: () => ({ authorId: post.authorId, status: "live" })
    })
  })

  it("keeps the other actions when one rule is broken", () => {
    const Broken = PostRules.create("posts:publish", {
      check: () => Condition.always,
      // @ts-expect-error Property 'status' is missing
      set: ({ principal }) => ({ authorId: principal.subject.id })
    })
    const BrokenPermissions = Permission.make(CurrentPrincipal, { rules: [Broken] })
    expect(BrokenPermissions.create).type.toBeCallableWith("posts:create", payload)
    expect(BrokenPermissions.require).type.toBeCallableWith("posts:read", post)
    expect(BrokenPermissions.layer).type.toBe<Layer.Layer<Authorizer.Authorizer>>()
  })

  it("collects the services custom conditions require", () => {
    const Rules = Permission.rules(CurrentPrincipal, Post).action("posts:audit", {
      filter: () => Condition.custom("recent", () => Effect.map(Clock.currentTimeMillis, (now) => now > 0))
    })
    expect<Permission.ServicesOf<typeof Rules>>().type.toBe<never>()
    const WithServices = Rules.action("posts:archive", {
      filter: () => Condition.custom("archivable", () => Effect.as(CurrentPrincipal, true))
    })
    expect<Permission.ServicesOf<typeof WithServices>>().type.toBe<CurrentPrincipal>()
  })
})

describe("Permissions", () => {
  it("creates a Model's insert variant from its jsonCreate payload", () => {
    expect(Permissions.create("posts:create", payload)).type.toBe<
      Effect.Effect<
        Permission.Authorized<"posts:create", typeof Post.insert.Type>,
        PermissionError.PermissionError,
        CurrentPrincipal | Authorizer.Authorizer
      >
    >()
    expect(Permissions.create).type.not.toBeCallableWith("posts:create", {})
  })

  it("creates any other resource from its constructor input", () => {
    expect(Permissions.create("notes:create", { id: "n-1", authorId: "p-1", body: "" })).type.toBe<
      Effect.Effect<
        Permission.Authorized<"notes:create", Note>,
        PermissionError.PermissionError,
        CurrentPrincipal | Authorizer.Authorizer
      >
    >()
  })

  it("offers create only create actions, and the other methods only the rest", () => {
    // @ts-expect-error Argument of type 'string' is not assignable to parameter of type 'NotACreateAction<"posts:read">'
    Permissions.create("posts:read", payload)
    // @ts-expect-error Argument of type 'string' is not assignable to parameter of type 'IsACreateAction<"posts:create">'
    Permissions.require("posts:create", post)
    // @ts-expect-error Argument of type 'string' is not assignable to parameter of type 'IsACreateAction<"posts:create">'
    Permissions.can("posts:create", post)
    expect(Permissions.require("posts:update", post)).type.toBe<
      Effect.Effect<
        Permission.Authorized<"posts:update", Post>,
        PermissionError.PermissionError,
        CurrentPrincipal | Authorizer.Authorizer
      >
    >()
    expect(Permissions.filter).type.toBeCallableWith("posts:create")
  })

  it("updates a Model's update variant from part of its jsonUpdate payload", () => {
    expect(Permissions.update("posts:update", post, { title: "Renamed" })).type.toBe<
      Effect.Effect<
        Permission.Authorized<"posts:update", typeof Post.update.Type>,
        PermissionError.PermissionError,
        CurrentPrincipal | Authorizer.Authorizer
      >
    >()
    // `GeneratedByApp` and `GeneratedByDb` fields aren't in the payload
    // @ts-expect-error Object literal may only specify known properties, and 'authorId' does not exist
    Permissions.update("posts:update", post, { authorId: post.authorId })
    // @ts-expect-error Object literal may only specify known properties, and 'id' does not exist
    Permissions.update("posts:update", post, { id: 2 })
    // @ts-expect-error Argument of type 'string' is not assignable to parameter of type 'IsACreateAction<"posts:create">'
    Permissions.update("posts:create", post, {})
  })

  it("takes one payload shape for signed-in principals and another for the system", () => {
    expect<Permission.PayloadOf<typeof PostRules, "posts:create">>().type.toBe<
      // Signed in: `set` fills authorId and status
      | { readonly title: string; readonly authorId?: never; readonly status?: never }
      // The system principal gets no `set`, so it passes them
      | { readonly title: string; readonly authorId: ProfileId; readonly status: "draft" | "live" }
    >()
    expect(Permissions.create).type.toBeCallableWith("posts:create", {
      ...payload,
      authorId: post.authorId,
      status: "live"
    })
    // @ts-expect-error Property 'authorId' is missing in type '{ status: "live"; title: string; }'
    Permissions.create("posts:create", { ...payload, status: "live" })
    // An action without `set` has one shape
    expect<Permission.PayloadOf<typeof NoteRules, "notes:create">>().type.toBe<
      { readonly id: string; readonly authorId: string; readonly body: string }
    >()
  })

  it("takes one patch shape for signed-in principals and another for the system", () => {
    expect<Permission.PatchOf<typeof PostRules, "posts:approve">>().type.toBe<
      | { readonly title?: string; readonly status?: never }
      | { readonly title?: string; readonly status?: "draft" | "live" }
    >()
    expect(Permissions.update).type.toBeCallableWith("posts:approve", post, { status: "live" })
    // @ts-expect-error Object literal may only specify known properties, and 'status' does not exist
    Permissions.update("posts:update", post, { status: "live" })
  })

  it("updates any other resource from part of its constructor input", () => {
    expect(Permissions.update("notes:edit", note, { body: "" })).type.toBe<
      Effect.Effect<
        Permission.Authorized<"notes:edit", Note>,
        PermissionError.PermissionError,
        CurrentPrincipal | Authorizer.Authorizer
      >
    >()
  })
})
