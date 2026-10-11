package authz

import (
	"errors"

	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
)

// ErrNoRegistry means authz.Provider was never registered. It is a
// misconfiguration, so it answers 500 rather than 403: an operator must not
// be sent looking for a permissions problem that does not exist.
var ErrNoRegistry = errors.New("authz: no registry is configured; register authz.Provider")

// Get returns the application's registry.
func Get(a app.App) (*Registry, bool) {
	return app.Lookup[*Registry](a)
}

// Can reports whether the request may perform ability on resource.
//
// With no registry configured it reports false — a page deciding whether to
// show an Edit button should hide it, not crash. Authorize is the one that
// distinguishes a misconfiguration from a refusal, because it is the one
// whose answer becomes a status code.
func Can[R any](c app.Context, ability string, resource R) bool {
	return Explain(c, ability, resource).Allowed
}

// Explain is Can with the reason, for a handler that wants to show it.
func Explain[R any](c app.Context, ability string, resource R) Decision {
	registry, ok := Get(c.App())
	if !ok {
		return Deny(ErrNoRegistry.Error())
	}
	return registry.decide(c, ability, resource, true)
}

// Allowed reports whether the request may perform a resourceless ability.
func Allowed(c app.Context, ability string) bool {
	return ExplainGate(c, ability).Allowed
}

// ExplainGate is Allowed with the reason.
func ExplainGate(c app.Context, ability string) Decision {
	registry, ok := Get(c.App())
	if !ok {
		return Deny(ErrNoRegistry.Error())
	}
	return registry.decide(c, ability, nil, false)
}

// Authorize returns an error a handler can return directly:
//
//	if err := authz.Authorize(c, "launch.update", launch); err != nil {
//	    return err
//	}
//
// The error carries the status, so the framework's error mapping turns it
// into 403 — or 401 for an anonymous request, because telling someone who is
// not signed in that they are forbidden invites them to give up rather than
// sign in.
func Authorize[R any](c app.Context, ability string, resource R) error {
	return asError(c, Explain(c, ability, resource))
}

// AuthorizeGate is Authorize for a resourceless ability.
func AuthorizeGate(c app.Context, ability string) error {
	return asError(c, ExplainGate(c, ability))
}

func asError(c app.Context, decision Decision) error {
	if decision.Allowed {
		return nil
	}
	if _, ok := Get(c.App()); !ok {
		// A missing registry is the application's mistake, not the caller's.
		return c.InternalServerError(ErrNoRegistry)
	}
	if !auth.IsAuthenticated(c) && auth.AuthUser(c) == nil {
		return c.Unauthorized(errors.New(reasonOr(decision, "not authenticated")))
	}
	return c.Forbidden(errors.New(reasonOr(decision, "forbidden")))
}

func reasonOr(d Decision, fallback string) string {
	if d.Reason != "" {
		return d.Reason
	}
	return fallback
}
