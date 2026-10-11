package authz

import (
	"github.com/lemmego/api/app"
	"github.com/lemmego/auth"
)

// OwnedBy is the rule most resources need: the actor is the resource's owner.
//
// ownerID extracts the owner's id from the resource, as a string, because
// that is the type auth.UserProvider.GetID already speaks and the type a
// credential carries. Comparing ids rather than loading the owner is the
// point — the owner id is already on the row you loaded, so an ownership
// check costs no query at all.
func OwnedBy[U auth.UserProvider, R any](ownerID func(R) string) func(app.Context, U, R) Decision {
	return func(_ app.Context, user U, resource R) Decision {
		owner := ownerID(resource)
		// An empty id on either side must never match. A resource with no
		// owner and a user with no id would otherwise authorise each other.
		if owner == "" || user.GetID() == "" {
			return Deny("ownership could not be established")
		}
		if owner == user.GetID() {
			return Allow()
		}
		return Deny("you do not own this")
	}
}

// AnyOf allows when any rule allows, and reports the last reason otherwise.
// Use it for "the owner or a moderator".
func AnyOf[U, R any](rules ...func(app.Context, U, R) Decision) func(app.Context, U, R) Decision {
	return func(c app.Context, user U, resource R) Decision {
		decision := Deny("no rule allowed this")
		for _, rule := range rules {
			if decision = rule(c, user, resource); decision.Allowed {
				return decision
			}
		}
		return decision
	}
}

// AllOf allows only when every rule allows, and stops at the first refusal so
// the reason is the first thing that actually blocked.
func AllOf[U, R any](rules ...func(app.Context, U, R) Decision) func(app.Context, U, R) Decision {
	return func(c app.Context, user U, resource R) Decision {
		for _, rule := range rules {
			if decision := rule(c, user, resource); !decision.Allowed {
				return decision
			}
		}
		return Allow()
	}
}
