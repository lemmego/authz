package authz

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/lemmego/api/app"
	"github.com/lemmego/apptest"
	"github.com/lemmego/auth"
)

// collector records what the observers were told, in order.
type collector struct {
	mu   sync.Mutex
	seen []Observation
	ctxs []context.Context
}

func (c *collector) observe(ctx context.Context, o Observation) {
	c.mu.Lock()
	c.seen = append(c.seen, o)
	c.ctxs = append(c.ctxs, ctx)
	c.mu.Unlock()
}

func (c *collector) only(t *testing.T) Observation {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) != 1 {
		t.Fatalf("observed %d decisions, want 1: %+v", len(c.seen), c.seen)
	}
	return c.seen[0]
}

// watching returns policies that register the ownership rules and an
// observer on the same registry.
func watching(c *collector, policies func(*Registry)) func(*Registry) {
	return func(r *Registry) {
		policies(r)
		r.Observe(c.observe)
	}
}

func TestAnAllowIsObserved(t *testing.T) {
	var seen collector
	a := boot(t, watching(&seen, ownershipPolicies))

	a.Get("/launch").ActingAs("1").Send().AssertStatus(http.StatusOK)

	got := seen.only(t)
	if got.Ability != "launch.update" || !got.Decision.Allowed {
		t.Fatalf("observation = %+v", got)
	}
	if !got.HasResource {
		t.Error("HasResource is false for a check made with a resource")
	}
	if l, ok := got.Resource.(*launch); !ok || l.ID != 10 {
		t.Errorf("Resource = %#v, want the launch that was checked", got.Resource)
	}
	if u, ok := got.Subject.(*user); !ok || u.ID != "1" {
		t.Errorf("Subject = %#v, want the authenticated user", got.Subject)
	}
}

// A denial has to carry its reason, because a view that says "denied" without
// saying why is not worth opening — which is the same argument that put the
// reason on Decision in the first place.
func TestADenialIsObservedWithItsReason(t *testing.T) {
	var seen collector
	a := boot(t, watching(&seen, ownershipPolicies))

	a.Get("/launch").ActingAs("2").Send().AssertStatus(http.StatusForbidden)

	got := seen.only(t)
	if got.Decision.Allowed {
		t.Fatal("a refusal was observed as an allow")
	}
	if got.Decision.Reason == "" {
		t.Error("the reason did not reach the observer")
	}
}

// The denials this package reaches without consulting a rule are the ones
// worth seeing, and they are the ones a hook placed inside the rule body
// would miss entirely.
//
// An unregistered ability is a typo or a rule deleted in a refactor. Failing
// closed turns it into a 403 rather than an open door, and the cost of that
// trade is that the 403 looks like an ordinary refusal. An observer is how it
// stops looking like one.
func TestTheDenialsReachedWithoutARuleAreObservedToo(t *testing.T) {
	cases := []struct {
		name     string
		policies func(*Registry)
		send     func(a *apptest.App)
		reason   string
	}{
		{
			name: "an unregistered ability",
			// launch.update is deliberately not registered.
			policies: func(r *Registry) {
				Gate(r, "launch.create", func(app.Context, *user) Decision { return Allow() })
			},
			send:   func(a *apptest.App) { a.Get("/launch").ActingAs("1").Send() },
			reason: "no rule is registered",
		},
		{
			// The key, not the sentence, and that is the right thing for an
			// observer: a reason is resolved to prose at the error boundary,
			// in the reader's language, so a debugging record holding the
			// rendered text would change with whoever happened to trigger
			// the request. The key is the stable identity.
			name:     "an anonymous request",
			policies: ownershipPolicies,
			send:     func(a *apptest.App) { a.Get("/launch/can").Send() },
			reason:   KeyUnauthenticated,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var seen collector
			a := boot(t, watching(&seen, test.policies))

			test.send(a)

			got := seen.only(t)
			if got.Decision.Allowed {
				t.Fatal("observed an allow")
			}
			if !strings.Contains(got.Decision.Reason, test.reason) {
				t.Errorf("reason = %q, want it to say %q", got.Decision.Reason, test.reason)
			}
		})
	}
}

// A gate takes no resource, and an observer must be able to tell that from a
// rule called with a nil one — otherwise every gate reads as a bug.
func TestAGateIsObservedWithNoResource(t *testing.T) {
	var seen collector
	a := boot(t, watching(&seen, ownershipPolicies))

	a.Post("/launches").ActingAs("1").Send().AssertStatus(http.StatusOK)

	got := seen.only(t)
	if got.Ability != "launch.create" {
		t.Fatalf("ability = %q", got.Ability)
	}
	if got.HasResource || got.Resource != nil {
		t.Errorf("a gate was observed as having a resource: %+v", got)
	}
}

// The context is most of the value: an entry that cannot be attributed to a
// request is a line in a list rather than part of a story. The value is put
// there by an HTTP middleware because that is where observe's request id
// comes from.
func TestTheObserverIsHandedTheRequestsContext(t *testing.T) {
	type key struct{}

	var seen collector
	a := apptest.New(t,
		apptest.WithProviders(authProvider(), &Provider{Policies: watching(&seen, ownershipPolicies)}),
		apptest.WithHTTPMiddlewares(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(
					context.WithValue(r.Context(), key{}, "this request")))
			})
		}),
		apptest.WithRoutes(func(engine app.App) {
			engine.Router().Get("/launch", auth.OptionalAuth, func(c app.Context) error {
				return c.JSON(app.M{"can": Can(c, "launch.update", adaLaunch())})
			})
		}),
	)

	a.Get("/launch").ActingAs("1").Send().AssertStatus(http.StatusOK)

	seen.mu.Lock()
	defer seen.mu.Unlock()
	if len(seen.ctxs) != 1 {
		t.Fatalf("observed %d decisions, want 1", len(seen.ctxs))
	}
	if got := seen.ctxs[0].Value(key{}); got != "this request" {
		t.Errorf("the observer was handed a context carrying %v, not the request's", got)
	}
}

// A registry asked outside a request still works, and the observer is handed
// a usable context rather than a nil one.
func TestAnObserverPanicDoesNotFailTheRequest(t *testing.T) {
	var seen collector
	a := boot(t, watching(&seen, func(r *Registry) {
		ownershipPolicies(r)
		r.Observe(func(context.Context, Observation) { panic("the observer is broken") })
	}))

	// The panicking observer is registered second, so this also asserts the
	// first one still ran — a recover around the whole loop rather than
	// around each member would have cost it nothing, but the reverse order
	// would have cost the second observer its event.
	a.Get("/launch").ActingAs("1").Send().AssertStatus(http.StatusOK)

	if got := seen.only(t); !got.Decision.Allowed {
		t.Errorf("observation = %+v", got)
	}
}

// Nobody listening is the normal case, and it must not change an answer.
func TestObservingChangesNoDecision(t *testing.T) {
	var seen collector
	watched := boot(t, watching(&seen, ownershipPolicies))
	unwatched := boot(t, ownershipPolicies)

	for _, a := range []*apptest.App{watched, unwatched} {
		a.Get("/launch").ActingAs("1").Send().AssertStatus(http.StatusOK)
		a.Get("/launch").ActingAs("2").Send().AssertStatus(http.StatusForbidden)
		a.Get("/launch").Send().AssertStatus(http.StatusUnauthorized)
	}
}

// A registry asked outside a request — a test, a command, a shape mismatch
// caught before any context exists — still notifies, and hands the observer a
// usable context rather than a nil one. A nil context passed to
// slog.ErrorContext or to a store would be the observer's problem to discover
// at the worst moment.
func TestADecisionMadeWithNoRequestIsStillObserved(t *testing.T) {
	var seen collector

	registry := NewRegistry()
	Register(registry, "launch.update", ownLaunch())
	Gate(registry, "launch.create", func(app.Context, *user) Decision { return Allow() })
	registry.Observe(seen.observe)

	if d := registry.decide(nil, "launch.create", adaLaunch(), true); d.Allowed {
		t.Fatal("a gate accepted a resource")
	}

	got := seen.only(t)
	if !strings.Contains(got.Decision.Reason, "takes no resource") {
		t.Errorf("reason = %q", got.Decision.Reason)
	}
	if seen.ctxs[0] == nil {
		t.Error("the observer was handed a nil context")
	}
}
