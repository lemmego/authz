// Package authz answers "may this request do this to that".
//
// auth establishes who is making a request. authz decides what they are
// allowed to do, which is a separate question with a separate answer, and the
// two are deliberately separate packages: an application can authenticate
// without authorising anything, and a rule can be written against a request
// that was authenticated by something other than this framework's auth.
//
// A rule is registered once at boot and asked per request:
//
//	authz.Register(r, "launch.update", authz.OwnedBy[*models.User, *models.Launch](
//	    func(l *models.Launch) string { return strconv.FormatUint(l.UserID, 10) },
//	))
//
//	if err := authz.Authorize(c, "launch.update", launch); err != nil {
//	    return err // 403
//	}
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"

	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
)

// Decision is the outcome of one check.
//
// The reason travels with it so a 403 can say something true. "Forbidden" is
// a wasted response: the person reading it already knows that much, and the
// developer reading the log learns nothing.
type Decision struct {
	Allowed bool
	Reason  string
}

// Allow permits the action.
func Allow() Decision { return Decision{Allowed: true} }

// Deny refuses it, with a reason the handler may show.
func Deny(reason string) Decision { return Decision{Reason: reason} }

// rule is a registered check, with the types it was registered for erased.
//
// Erasure happens at registration rather than at call time, so the assertions
// live in one closure built once with both types in scope. A rule body
// therefore never sees a value of the wrong type, and a mismatch is a Deny
// rather than a panic — an authorization layer that can panic is a denial of
// service.
type rule struct {
	needsResource bool
	check         func(c app.Context, subject, resource any) Decision
}

// Registry holds an application's rules. One per application, built at boot.
type Registry struct {
	mu        sync.RWMutex
	rules     map[string]rule
	before    []func(c app.Context, subject any) (Decision, bool)
	observers []Observer
}

// NewRegistry returns an empty registry. Most applications get one from
// Provider instead.
func NewRegistry() *Registry {
	return &Registry{rules: map[string]rule{}}
}

// Register binds an ability on resource type R to a rule.
//
// U and R are inferred at the call site, so the rule body is fully typed:
//
//	authz.Register(r, "launch.update",
//	    func(c app.Context, u *models.User, l *models.Launch) authz.Decision {
//	        if l.UserID == u.ID { return authz.Allow() }
//	        return authz.Deny("not your launch")
//	    })
//
// Registering the same ability twice panics. It happens at boot, where a
// panic is a clear error message rather than an outage, and the alternative —
// silently taking one of the two — is a rule that is enforced on some days
// and not others depending on file order.
func Register[U, R any](r *Registry, ability string, check func(c app.Context, user U, res R) Decision) {
	r.set(ability, rule{
		needsResource: true,
		check: func(c app.Context, subject, resource any) Decision {
			user, ok := subject.(U)
			if !ok {
				return Deny("not authenticated as the expected user type")
			}
			res, ok := resource.(R)
			if !ok {
				return Deny(fmt.Sprintf("%s does not apply to %T", ability, resource))
			}
			return check(c, user, res)
		},
	})
}

// Gate binds an ability that has no resource: "launch.create",
// "admin.access", "dashboard.view".
func Gate[U any](r *Registry, ability string, check func(c app.Context, user U) Decision) {
	r.set(ability, rule{
		needsResource: false,
		check: func(c app.Context, subject, _ any) Decision {
			user, ok := subject.(U)
			if !ok {
				return Deny("not authenticated as the expected user type")
			}
			return check(c, user)
		},
	})
}

// Before runs ahead of every check. Returning handled=true short-circuits
// with the Decision given.
//
// This is the administrator escape hatch, and the only place a blanket allow
// belongs. Keeping it in one place means there is one line to read when
// asking "who can bypass this", instead of an `if user.IsAdmin` scattered
// through every rule.
func Before[U any](r *Registry, fn func(c app.Context, user U) (Decision, bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.before = append(r.before, func(c app.Context, subject any) (Decision, bool) {
		user, ok := subject.(U)
		if !ok {
			return Decision{}, false
		}
		return fn(c, user)
	})
}

func (r *Registry) set(ability string, rl rule) {
	if ability == "" {
		panic("authz: an ability needs a name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.rules[ability]; taken {
		panic("authz: ability " + ability + " is already registered")
	}
	r.rules[ability] = rl
}

// Abilities lists the registered ability names, for a diagnostic command.
func (r *Registry) Abilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.rules))
	for name := range r.rules {
		names = append(names, name)
	}
	return names
}

// Observation is one authorization decision, as an observer sees it.
//
// Subject and Resource are the values the rule was asked about, so an
// observer can name them — a debugging view that says "denied" without
// saying denied what, to whom, is not worth opening. They are the
// application's own types, and an observer that records them is responsible
// for what it records: a user struct holds an email address and a password
// hash.
type Observation struct {
	// Ability is the name the check was made under, registered or not.
	Ability string

	// Subject is the authenticated user, or nil for an anonymous request.
	Subject any

	// Resource is what the ability was checked against, and HasResource
	// distinguishes a gate — which legitimately has none — from a rule
	// called with a nil one.
	Resource    any
	HasResource bool

	// Decision carries the outcome and the reason, including the reasons
	// this package produces itself: an unregistered ability, a gate called
	// with a resource, an anonymous request.
	Decision Decision
}

// Observer is told about every decision this registry makes.
//
// It runs synchronously on the goroutine that asked, after the decision is
// reached and before it is returned, and it is handed the request's context
// so an entry can be attributed to the request that caused it. A panic is
// contained: an observer must not be able to turn an authorization check into
// a 500.
//
// Every decision means every one, including the denials this package reaches
// without consulting a rule. Those are the interesting ones — a typo in an
// ability name is a silent 403 otherwise, which is the failure the fail-closed
// default deliberately trades for, and an observer is how you see it.
type Observer func(ctx context.Context, o Observation)

// Observe registers an observer. Additive, so an application's own does not
// displace a debugger's.
func (r *Registry) Observe(o Observer) {
	if o == nil {
		return
	}
	r.mu.Lock()
	r.observers = append(r.observers, o)
	r.mu.Unlock()
}

// decide is the one path every public entry point funnels through.
//
// It is a wrapper so that the observers fire on every outcome rather than on
// the ones somebody remembered: evaluate has six returns, and a notify call
// per return is a notify call missing from the seventh.
func (r *Registry) decide(c app.Context, ability string, resource any, hasResource bool) Decision {
	subject := subjectOf(c)
	decision := r.evaluate(c, subject, ability, resource, hasResource)
	r.notify(c, Observation{
		Ability:     ability,
		Subject:     subject,
		Resource:    resource,
		HasResource: hasResource,
		Decision:    decision,
	})
	return decision
}

func (r *Registry) notify(c app.Context, o Observation) {
	r.mu.RLock()
	observers := r.observers
	r.mu.RUnlock()
	if len(observers) == 0 {
		return
	}

	// The request's context, so an observer can correlate. A registry asked
	// outside a request — a test, a command — has no context to offer, and
	// Background is the honest answer rather than a nil one.
	ctx := context.Background()
	if c != nil {
		if requestCtx := c.RequestContext(); requestCtx != nil {
			ctx = requestCtx
		}
	}

	for _, observe := range observers {
		deliver(ctx, observe, o)
	}
}

// deliver isolates an observer's panic. An authorization layer that can be
// made to panic is a denial of service, which is the reason a type mismatch
// inside a rule is a Deny rather than a crash — and an observer is code from
// somewhere else running on the same path.
func deliver(ctx context.Context, observe Observer, o Observation) {
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.ErrorContext(ctx, "authz: an observer panicked",
				"ability", o.Ability, "panic", recovered)
		}
	}()
	observe(ctx, o)
}

func (r *Registry) evaluate(c app.Context, subject any, ability string, resource any, hasResource bool) Decision {
	r.mu.RLock()
	rl, registered := r.rules[ability]
	before := append([]func(app.Context, any) (Decision, bool){}, r.before...)
	r.mu.RUnlock()

	// An unregistered ability is a Deny, never an Allow.
	//
	// The alternative — allowing what has no rule — means a typo in an
	// ability name silently opens the action, and a rule deleted in a
	// refactor silently opens it too. Failing closed turns both into a
	// visible 403 on the first request instead of an invisible hole.
	if !registered {
		return Deny(fmt.Sprintf("no rule is registered for %q", ability))
	}
	if rl.needsResource != hasResource {
		if hasResource {
			return Deny(fmt.Sprintf("%q is a gate and takes no resource", ability))
		}
		return Deny(fmt.Sprintf("%q needs a resource", ability))
	}

	for _, fn := range before {
		if decision, handled := fn(c, subject); handled {
			return decision
		}
	}

	// An anonymous request reaches no rule body. Every rule is written
	// against a user, and a nil subject asserted to *models.User would be a
	// typed nil — non-nil as an any, and a nil dereference on the first field
	// access inside the rule.
	if subject == nil {
		return Deny(KeyUnauthenticated)
	}

	return rl.check(c, subject, resource)
}

// subjectOf reads the authenticated user off the request.
//
// It deliberately does not call auth.Check. Check is already memoised per
// request by whichever of auth.Protected, auth.OptionalAuth or a group guard
// ran first, and calling it from here would reach auth.Get, which panics in
// an application that authenticates through a bearer guard without
// registering auth.Provider. So authz depends on auth for two symbols — the
// context key and the interface — and for nothing else.
//
// The typed-nil guard matters: a loader that returned (*models.User)(nil)
// hands back a non-nil any, which would satisfy a type assertion and then
// dereference to nothing.
func subjectOf(c app.Context) any {
	if c == nil {
		return nil
	}
	subject := auth.AuthUser(c)
	if subject == nil {
		return nil
	}
	value := reflect.ValueOf(subject)
	switch value.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		if value.IsNil() {
			return nil
		}
	}
	return subject
}
