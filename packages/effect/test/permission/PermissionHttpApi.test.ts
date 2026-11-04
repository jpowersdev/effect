import { assert, describe, it } from "@effect/vitest"
import { Effect, Exit, FileSystem, Layer, Path, Schema } from "effect"
import { Etag, HttpPlatform } from "effect/http"
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup, HttpApiMiddleware, HttpApiTest } from "effect/http-api"
import { Authorizer, Permission, PermissionError, PermissionHttpApi, Principal } from "effect/permission"
import { CurrentPrincipal, manager, type Member, memberships, nurse, Permissions, Unit, units } from "./utils.ts"

class Authentication extends HttpApiMiddleware.Service<
  Authentication,
  { provides: CurrentPrincipal }
>()("test/permission/Authentication") {}

class Authorize extends HttpApiMiddleware.Service<
  Authorize,
  {
    requires: CurrentPrincipal
    provides: Authorizer.Authorizer
  }
>()("test/permission/Authorize", {
  error: PermissionError.PermissionError
}) {}

const UnitsGroup = HttpApiGroup.make("units")
  .add(
    HttpApiEndpoint.get("list", "/units", { success: Schema.Array(Unit) })
      .annotate(Permissions.Required, "units:read"),
    HttpApiEndpoint.patch("rename", "/units/:id", {
      params: { id: Schema.String },
      payload: Schema.Struct({ name: Schema.String }),
      success: Unit
    }).annotate(Permissions.Required, "units:update"),
    HttpApiEndpoint.get("health", "/health", { success: Schema.String })
      .annotate(Permissions.Required, Permission.Public)
  )
  .middleware(Authorize)
  .middleware(Authentication)

const Api = HttpApi.make("api").add(UnitsGroup)

const UnitsLive = HttpApiBuilder.group(Api, "units", (handlers) =>
  handlers
    .handle("list", () =>
      Effect.filter(units, (unit) =>
        Permissions.can("units:read", unit).pipe(Effect.map(Authorizer.isAllow))).pipe(
          Effect.orDie
        ))
    .handle("rename", ({ params, payload }) =>
      Permissions.update(
        "units:update",
        units.find((unit) =>
          unit.id === params.id
        )!,
        { name: payload.name }
      ))
    .handle("health", () => Effect.succeed("ok")))

const TestServices = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

const client = (principal: Principal.Principal<Member>) =>
  HttpApiTest.groups(Api, ["units"]).pipe(
    Effect.provide(UnitsLive),
    Effect.provide(PermissionHttpApi.layer(Authorize, Permissions, { api: Api })),
    Effect.provide(
      Layer.succeed(Authentication, (httpEffect) => Effect.provideService(httpEffect, CurrentPrincipal, principal))
    ),
    Effect.provide(Permissions.layer.pipe(Layer.provide(Authorizer.layerRelationsMemory(memberships)))),
    Effect.provide(TestServices)
  )

describe("PermissionHttpApi", () => {
  it.effect("lets allowed requests through and filters in the handler", () =>
    Effect.gen(function*() {
      const api = yield* client(nurse)
      const visible = yield* api.units.list()
      assert.deepStrictEqual(visible.map((unit) => unit.id), ["u-1", "u-2"])
    }))

  it.effect("rejects an action the principal could never perform before the handler runs", () =>
    Effect.gen(function*() {
      const api = yield* client(nurse)
      const error = yield* Effect.flip(api.units.rename({ params: { id: "u-1" }, payload: { name: "x" } }))
      assert.instanceOf(error, PermissionError.PermissionDenied)
      assert.strictEqual(error.reason, "NoPermission")
    }))

  it.effect("checks the resource in the handler", () =>
    Effect.gen(function*() {
      const api = yield* client(manager)
      const renamed = yield* api.units.rename({ params: { id: "u-1" }, payload: { name: "Intensive Care" } })
      assert.strictEqual(renamed.name, "Intensive Care")
      const error = yield* Effect.flip(api.units.rename({ params: { id: "u-3" }, payload: { name: "x" } }))
      assert.instanceOf(error, PermissionError.PermissionDenied)
    }))

  it.effect("lets guests through to public endpoints and answers 401 elsewhere", () =>
    Effect.gen(function*() {
      const api = yield* client(Principal.guest)
      assert.strictEqual(yield* api.units.health(), "ok")
      const error = yield* Effect.flip(api.units.list())
      assert.instanceOf(error, PermissionError.Unauthenticated)
      assert.strictEqual(error.action, "units:read")
    }))

  it.effect("fails to start when an endpoint is not covered", () =>
    Effect.gen(function*() {
      const Unguarded = HttpApi.make("unguarded").add(
        HttpApiGroup.make("units").add(
          HttpApiEndpoint.get("list", "/units", { success: Schema.String }).annotate(
            Permissions.Required,
            "units:read"
          ),
          HttpApiEndpoint.get("other", "/other", { success: Schema.String })
        )
      )
      assert.deepStrictEqual(PermissionHttpApi.validate(Unguarded, Authorize, Permissions), [
        "units.list requires \"units:read\" but is not guarded by test/permission/Authorize",
        "units.other has no required action; annotate it with an action or Permission.Public"
      ])
      const exit = yield* Effect.exit(
        Layer.build(PermissionHttpApi.layer(Authorize, Permissions, { api: Unguarded })).pipe(
          Effect.provide(Authorizer.layerDenyAll),
          Effect.scoped
        )
      )
      assert.isTrue(Exit.hasDies(exit))
    }))
})
