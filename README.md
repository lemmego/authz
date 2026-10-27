# lemmego/authz

Authorization for Lemmego applications: typed policies, registered once at
boot and asked per request.

```go
import "github.com/lemmego/authz"

// at boot
authz.Register(r, "launch.update", authz.OwnedBy[*models.User, *models.Launch](
    func(l *models.Launch) string { return strconv.FormatUint(l.UserID, 10) },
))

// in a handler
if err := authz.Authorize(c, "launch.update", launch); err != nil {
    return err // 403, or 401 if nobody is signed in
}
```

## How it relates to `auth`

`auth` establishes **who** is making a request. `authz` decides **what they
may do**, which is a separate question with a separate answer. Keeping them
apart means an application can authenticate without authorising anything, and
a rule can be written against a request that something other than
`lemmego/auth` authenticated.

## Install

```bash
go get github.com/lemmego/authz
```

Register the provider in `bootstrap/providers.go`, with one function that
registers every rule:

```go
func LoadProviders() []app.Provider {
    return []app.Provider{
        &ormconnector.Provider{},
        &authz.Provider{Policies: policies.Register},
    }
}
```

`Policies` is called once, at boot, with the registry — so every rule in the
application is reachable from one function and the whole set is reviewable in
one place.

```go
// internal/policies/policies.go
func Register(r *authz.Registry) {
    authz.Register(r, "launch.update", launchOwner)
    authz.Register(r, "comment.delete", commentOwnerOrModerator)
    authz.Gate(r, "launch.create", verifiedEmail)
}
```

## Two kinds of ability

|  | Registered with | Asked with | For |
|---|---|---|---|
| **Resource** | `Register[U, R]` | `Can`, `Explain`, `Authorize` | "may you edit *this* launch" |
| **Gate** | `Gate[U]` | `Allowed`, `ExplainGate`, `AuthorizeGate` | "may you create launches at all" |

The two are **not interchangeable**. Asking a resource ability through
`AuthorizeGate` is refused rather than silently passed a nil resource, because
a rule written to inspect a resource and handed none would read as a denial of
everything — or, worse, as a pass.

## Decisions carry a reason

```go
type Decision struct {
    Allowed bool
    Reason  string
}

authz.Allow()
authz.Deny("only the author can edit a launch")
```

The reason travels with the decision so a 403 can say something true.
"Forbidden" is a wasted response: the person reading it already knows that
much, and the developer reading the log learns nothing.

## Writing a rule

A rule is a function. It receives the context, the **typed** user and the
**typed** resource:

```go
func launchOwner(c app.Context, u *models.User, l *models.Launch) authz.Decision {
    if l.UserID == u.ID {
        return authz.Allow()
    }
    return authz.Deny("only the author can edit a launch")
}

authz.Register(r, "launch.update", launchOwner)
```

The type parameters are inferred from the function, and the registry stores
the types alongside the rule. A resource of the wrong type is **denied, not
panicked** — a bug in a route table should be a 403 in one place, not a 500
across the application.

### Combinators

```go
authz.OwnedBy[*models.User, *models.Launch](ownerID)  // compares ids, no query
authz.AnyOf(isOwner, isModerator)                     // first Allow wins
authz.AllOf(isOwner, isPublished)                     // first Deny wins
```

`OwnedBy` takes a function returning the owner's id as a string and compares
it to `auth.UserID`. It issues **no query**: the resource is already loaded,
so ownership costs nothing. It refuses an empty identifier on either side,
because `"" == ""` would make an unsaved resource owned by an anonymous
visitor.

### `Before` for an administrator

```go
authz.Before(r, func(c app.Context, u *models.User) (authz.Decision, bool) {
    if u.IsAdmin {
        return authz.Allow(), true // true: stop here
    }
    return authz.Decision{}, false // false: carry on to the rule
})
```

The second return is what makes this usable in both directions: `true` means
the decision stands, so a `Before` can grant everything to an administrator
**or** deny everything during a read-only maintenance window.

## Asking

| Call | Returns | Use when |
|---|---|---|
| `Can(c, ability, res)` | `bool` | Deciding whether to render a button |
| `Explain(c, ability, res)` | `Decision` | You want the reason |
| `Authorize(c, ability, res)` | `error` | Guarding a write; return it |
| `Allowed(c, ability)` | `bool` | Gate, in a template |
| `AuthorizeGate(c, ability)` | `error` | Gate, guarding a write |

`Authorize` returns an error carrying its own status, so the framework's error
mapping turns it into **403** — or **401** for an anonymous request, because
telling someone who is not signed in that they are forbidden invites them to
give up rather than sign in.

`Can` never fails the request, which is what makes it safe in a props builder:

```go
props["can_edit"] = authz.Can(c, "launch.update", launch)
```

## Middleware

When the resource comes from a route parameter, `Owns` is better than calling
`Authorize` in the handler — because **the middleware's load is the handler's
load**:

```go
r.Put("/launch/{slug}",
    auth.Protected,
    authz.Owns("launch.update", loadLaunchBySlug),
    handlers.UpdateLaunch,
)

func UpdateLaunch(c app.Context) error {
    launch, _ := authz.Resource[*models.Launch](c)   // already loaded
    …
}
```

That keeps an ownership check at **one query per request** instead of two. A
load error is returned as-is, so a missing row becomes whatever the
repository's not-found maps to — usually 404, which is the right answer and
not something `authz` should be deciding.

`Gated` is the resourceless form, and belongs after `auth.Protected`:

```go
r.Post("/launch", auth.Protected, authz.Gated("launch.create"), handlers.CreateLaunch)
```

## Limitations

No roles or permissions tables, no ABAC, no policy caching. A rule is a Go
function over data you have already loaded; the moment it needs its own
storage it stops being a policy and becomes a feature, and it should live in
the application where it can be migrated and tested like anything else.

## Failure modes

| Situation | Result |
|---|---|
| Ability never registered | Denied, and logged. Not allowed — a typo must not open a route. |
| No registry (provider not registered) | **500**, not 403: the application's mistake, not the caller's. |
| Resource of the wrong type | Denied, with a reason naming both types. Never a panic. |
| Typed nil subject (`(*User)(nil)`) | Not authenticated → 401. A non-nil interface holding a nil pointer is the classic Go trap and is checked for explicitly. |
| Same ability registered twice | **Panics at boot.** Two rules for one name means one of them never runs, and finding out in production is worse than not starting. |

## Testing

```bash
go test ./...
GOWORK=off go test ./...   # as a published module
```

The suite covers each row of the table above, including that an anonymous
request gets 401 rather than 403 and that gate and resource abilities cannot
be swapped.
