import { Clock, Context, Effect, Schema } from "effect"
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
  createdAt: Model.DateTimeInsert
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

const NoteRules = Permission.rules(CurrentPrincipal, Note)
  .create("notes:create", { check: () => Condition.always })

const Permissions = Permission.make(CurrentPrincipal, { rules: [PostRules, NoteRules] })

declare const post: Post
declare const payload: typeof Post.jsonCreate.Type

describe("Principal", () => {
  it("keeps a branded subject id and widens any other", () => {
    expect(Principal.make({ subject: "p-1", attributes: {} })).type.toBe<Principal.Authenticated<{}, string>>()
    expect(Principal.make({ subject: ProfileId.make("p-1"), attributes: {} })).type.toBe<
      Principal.Authenticated<{}, ProfileId>
    >()
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

  it("types create rules against the value create builds", () => {
    PostRules.create("posts:publish", {
      // @ts-expect-error Property 'id' does not exist on type 'ObjectRefs<{ readonly authorId: string & Brand<"ProfileId">;
      check: ({ resource: post }) => Condition.eq(post.id, 1),
      set: ({ principal }) => ({ authorId: principal.subject.id, status: "live" })
    })
  })

  it("only lets allowed refer to actions on existing resources declared before", () => {
    PostRules.action("posts:delete", {
      // @ts-expect-error Argument of type '"posts:create"' is not assignable to parameter of type '"posts:read" | "posts:update"'
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
})
