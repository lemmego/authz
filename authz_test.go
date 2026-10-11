package authz

import (
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/lemmego/api/app"
	"github.com/lemmego/apptest"
	"github.com/lemmego/auth"
)

type user struct {
	ID      string
	Email   string
	IsAdmin bool
}

func (u *user) GetID() string       { return u.ID }
func (u *user) GetUsername() string { return u.Email }
func (u *user) GetPassword() string { return "" }

type launch struct {
	ID     uint64
	UserID string
	Status string
}

var people = map[string]*user{
	"1": {ID: "1", Email: "ada@example.com"},
	"2": {ID: "2", Email: "grace@example.com"},
	"9": {ID: "9", Email: "root@example.com", IsAdmin: true},
}

func authProvider() *auth.Provider {
	return &auth.Provider{Opts: &auth.Opts{
		DisableSession: true,
		JwtSecret:      "authz-test",
		UserLoader: func(c app.Context, id string) (any, error) {
			if person, ok := people[id]; ok {
				return person, nil
			}
			return nil, auth.ErrUserNotFound
		},
	}}
}

// adaLaunch belongs to user 1.
func adaLaunch() *launch { return &launch{ID: 10, UserID: "1", Status: "published"} }

func ownLaunch() func(app.Context, *user, *launch) Decision {
	return OwnedBy[*user, *launch](func(l *launch) string { return l.UserID })
}

// boot builds an application with the given policies and one route per shape
// under test.
func boot(t *testing.T, policies func(*Registry)) *apptest.App {
	t.Helper()
	return apptest.New(t,
		apptest.WithProviders(authProvider(), &Provider{Policies: policies}),
		apptest.WithRoutes(func(a app.App) {
			// Authorize inside a handler.
			a.Router().Get("/launch", auth.OptionalAuth, func(c app.Context) error {
				if err := Authorize(c, "launch.update", adaLaunch()); err != nil {
					return err
				}
				return c.JSON(app.M{"ok": true})
			})
			// Can, for a page deciding what to render.
			a.Router().Get("/launch/can", auth.OptionalAuth, func(c app.Context) error {
				return c.JSON(app.M{"can": Can(c, "launch.update", adaLaunch())})
			})
			// A gate, as route middleware.
			a.Router().Post("/launches", auth.Protected, Gated("launch.create"), func(c app.Context) error {
				return c.JSON(app.M{"created": true})
			})
			// Owns, which loads once and hands the resource to the handler.
			a.Router().Put("/launch", auth.Protected,
				Owns("launch.update", func(c app.Context) (*launch, error) {
					loads(c)
					return adaLaunch(), nil
				}),
				func(c app.Context) error {
					l, ok := Resource[*launch](c)
					if !ok {
						return c.JSON(app.M{"reloaded": true})
					}
					return c.JSON(app.M{"id": l.ID, "loads": loadCount})
				})
		}),
	)
}

var loadCount int

func loads(app.Context) { loadCount++ }

func ownershipPolicies(r *Registry) {
	Register(r, "launch.update", ownLaunch())
	Gate(r, "launch.create", func(c app.Context, u *user) Decision { return Allow() })
}

// The ordinary case, both ways.
func TestTheOwnerIsAllowedAndOthersAreNot(t *testing.T) {
	a := boot(t, ownershipPolicies)

	a.Get("/launch").ActingAs("1").Send().AssertStatus(http.StatusOK)
	a.Get("/launch").ActingAs("2").Send().
		AssertStatus(http.StatusForbidden).
		AssertSee("you do not own this")
}

// An anonymous request gets 401, not 403. Telling someone who is not signed
// in that they are forbidden invites them to give up rather than sign in.
func TestAnonymousGets401Not403(t *testing.T) {
	a := boot(t, ownershipPolicies)
	a.Get("/launch").Send().AssertStatus(http.StatusUnauthorized)
}

// The decisive property of failing closed: a typo in an ability name, or a
// rule deleted in a refactor, must not open the action.
func TestAnUnregisteredAbilityIsRefused(t *testing.T) {
	a := boot(t, func(r *Registry) {
		// "launch.update" is deliberately not registered.
		Gate(r, "launch.create", func(c app.Context, u *user) Decision { return Allow() })
	})

	a.Get("/launch").ActingAs("1").Send().
		AssertStatus(http.StatusForbidden).
		AssertSee("no rule is registered")
}

// Can is for rendering, so it must answer false rather than erroring.
func TestCanAnswersWithoutFailingTheRequest(t *testing.T) {
	a := boot(t, ownershipPolicies)

	a.Get("/launch/can").ActingAs("1").Send().AssertStatus(http.StatusOK).AssertJSONPath("can", true)
	a.Get("/launch/can").ActingAs("2").Send().AssertStatus(http.StatusOK).AssertJSONPath("can", false)
	a.Get("/launch/can").Send().AssertStatus(http.StatusOK).AssertJSONPath("can", false)
}

func TestGatedMiddlewareGuardsAResourcelessAbility(t *testing.T) {
	a := boot(t, func(r *Registry) {
		Register(r, "launch.update", ownLaunch())
		Gate(r, "launch.create", func(c app.Context, u *user) Decision {
			if u.ID == "1" {
				return Allow()
			}
			return Deny("one launch per week")
		})
	})

	a.Post("/launches").ActingAs("1").Send().AssertStatus(http.StatusOK)
	a.Post("/launches").ActingAs("2").Send().
		AssertStatus(http.StatusForbidden).
		AssertSee("one launch per week")
}

// Owns must hand the handler what it loaded, so an ownership check costs one
// query rather than two. If the handler had to reload, that doubling would be
// invisible and permanent.
func TestOwnsLoadsOnceAndPassesTheResourceOn(t *testing.T) {
	a := boot(t, ownershipPolicies)
	loadCount = 0

	a.Put("/launch").ActingAs("1").Send().
		AssertStatus(http.StatusOK).
		AssertJSONPath("id", 10).
		AssertJSONPath("loads", 1)
}

func TestOwnsRefusesANonOwnerBeforeTheHandlerRuns(t *testing.T) {
	a := boot(t, ownershipPolicies)
	a.Put("/launch").ActingAs("2").Send().AssertStatus(http.StatusForbidden)
}

// Before is the administrator escape hatch, and the only place a blanket
// allow belongs.
func TestBeforeShortCircuitsForAnAdministrator(t *testing.T) {
	a := boot(t, func(r *Registry) {
		Before(r, func(c app.Context, u *user) (Decision, bool) {
			if u.IsAdmin {
				return Allow(), true
			}
			return Decision{}, false
		})
		Register(r, "launch.update", ownLaunch())
		Gate(r, "launch.create", func(c app.Context, u *user) Decision { return Allow() })
	})

	// The administrator owns nothing and is allowed anyway.
	a.Get("/launch").ActingAs("9").Send().AssertStatus(http.StatusOK)
	// A non-administrator still goes through the rule.
	a.Get("/launch").ActingAs("2").Send().AssertStatus(http.StatusForbidden)
}

// Before must be able to deny as well as allow — a suspended account is
// refused everything, in one place.
func TestBeforeCanDenyEverything(t *testing.T) {
	a := boot(t, func(r *Registry) {
		Before(r, func(c app.Context, u *user) (Decision, bool) {
			return Deny("account suspended"), true
		})
		Register(r, "launch.update", ownLaunch())
		Gate(r, "launch.create", func(c app.Context, u *user) Decision { return Allow() })
	})

	a.Get("/launch").ActingAs("1").Send().
		AssertStatus(http.StatusForbidden).
		AssertSee("account suspended")
}

// A rule registered for one resource type, asked about another, must refuse
// rather than panic. An authorization layer that panics is a denial of
// service.
func TestAMismatchedResourceTypeIsDeniedNotPanicked(t *testing.T) {
	registry := NewRegistry()
	Register(registry, "launch.update", ownLaunch())

	decision := registry.decide(nil, "launch.update", "not a launch", true)
	if decision.Allowed {
		t.Fatal("a string was authorised as a launch")
	}
	if decision.Reason == "" {
		t.Error("no reason given")
	}
}

// Asking a gate about a resource, or a resource rule with none, is a
// programming error — and must be refused rather than silently answered from
// the wrong rule.
func TestGateAndResourceAbilitiesAreNotInterchangeable(t *testing.T) {
	registry := NewRegistry()
	Register(registry, "launch.update", ownLaunch())
	Gate(registry, "launch.create", func(c app.Context, u *user) Decision { return Allow() })

	if d := registry.decide(nil, "launch.create", adaLaunch(), true); d.Allowed {
		t.Error("a gate accepted a resource")
	}
	if d := registry.decide(nil, "launch.update", nil, false); d.Allowed {
		t.Error("a resource rule was satisfied with no resource")
	}
}

// Registering the same ability twice is a boot-time panic rather than a
// silent overwrite, because a rule that depends on file order is enforced on
// some days and not others.
func TestRegisteringAnAbilityTwicePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate ability was allowed")
		}
	}()
	registry := NewRegistry()
	Register(registry, "launch.update", ownLaunch())
	Register(registry, "launch.update", ownLaunch())
}

// A typed nil must not authenticate. (*user)(nil) is non-nil as an any, so it
// would satisfy the assertion and then dereference to nothing inside the rule.
func TestATypedNilSubjectIsNotAuthenticated(t *testing.T) {
	registry := NewRegistry()
	Register(registry, "launch.update", func(c app.Context, u *user, l *launch) Decision {
		// Reached only if the guard fails; u.ID would panic.
		return Allow()
	})

	c := &nilSubjectContext{}
	if d := registry.decide(c, "launch.update", adaLaunch(), true); d.Allowed {
		t.Fatal("a typed nil user was authorised")
	}
}

// OwnedBy must never match on an empty id, or a resource with no owner and a
// user with no id would authorise each other.
func TestOwnedByRefusesEmptyIdentifiers(t *testing.T) {
	rule := OwnedBy[*user, *launch](func(l *launch) string { return l.UserID })

	if rule(nil, &user{ID: ""}, &launch{UserID: ""}).Allowed {
		t.Error("two empty ids matched")
	}
	if rule(nil, &user{ID: "1"}, &launch{UserID: ""}).Allowed {
		t.Error("an unowned resource matched")
	}
	if rule(nil, &user{ID: ""}, &launch{UserID: "1"}).Allowed {
		t.Error("a user with no id matched")
	}
	if !rule(nil, &user{ID: "1"}, &launch{UserID: "1"}).Allowed {
		t.Error("the owner was refused")
	}
}

func TestAnyOfAndAllOf(t *testing.T) {
	allow := func(app.Context, *user, *launch) Decision { return Allow() }
	deny := func(app.Context, *user, *launch) Decision { return Deny("no") }

	if !AnyOf(deny, allow)(nil, &user{ID: "1"}, adaLaunch()).Allowed {
		t.Error("AnyOf refused when one rule allowed")
	}
	if AnyOf(deny, deny)(nil, &user{ID: "1"}, adaLaunch()).Allowed {
		t.Error("AnyOf allowed when none did")
	}
	if AllOf(allow, deny)(nil, &user{ID: "1"}, adaLaunch()).Allowed {
		t.Error("AllOf allowed when one refused")
	}
	if !AllOf(allow, allow)(nil, &user{ID: "1"}, adaLaunch()).Allowed {
		t.Error("AllOf refused when all allowed")
	}
}

// Without authz.Provider, a check is a misconfiguration and not a refusal: an
// operator must not be sent looking for a permissions problem that does not
// exist.
func TestAMissingRegistryIsAServerError(t *testing.T) {
	a := apptest.New(t,
		apptest.WithProviders(authProvider()),
		apptest.WithRoutes(func(a app.App) {
			a.Router().Get("/launch", auth.Protected, func(c app.Context) error {
				return Authorize(c, "launch.update", adaLaunch())
			})
		}),
	)

	a.Get("/launch").ActingAs("1").Send().AssertStatus(http.StatusInternalServerError)
}

// nilSubjectContext hands back a typed nil from AuthUser, which is the shape a
// loader bug produces.
type nilSubjectContext struct {
	app.Context
}

func (c *nilSubjectContext) Get(key string) any {
	if key == auth.UserKey {
		var typedNil *user
		return typedNil
	}
	return nil
}

func (c *nilSubjectContext) App() app.App { return nil }

var _ = errors.New
var _ = strconv.Itoa
