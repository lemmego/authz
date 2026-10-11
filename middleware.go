package authz

import (
	"github.com/lemmego/api/app"
)

// resourceKey is where Owns leaves what it loaded. Namespaced, because
// c.Set is context.WithValue and an unqualified key collides with anything
// else using the same string.
const resourceKey = "authz:resource"

// Gated admits a request only when the resourceless ability passes. Place it
// after auth.Protected:
//
//	r.Post("/launches", auth.Protected, authz.Gated("launch.create"), handlers.LaunchStore)
func Gated(ability string) app.Handler {
	return func(c app.Context) error {
		if err := AuthorizeGate(c, ability); err != nil {
			return err
		}
		return c.Next()
	}
}

// Owns loads the resource, authorizes it, and leaves it on the request for
// the handler:
//
//	r.Put("/launches/{slug}", auth.Protected,
//	    authz.Owns("launch.update", loaders.LaunchBySlug),
//	    handlers.LaunchUpdate)
//
//	func LaunchUpdate(c app.Context) error {
//	    launch, _ := authz.Resource[*models.Launch](c)
//	    …
//	}
//
// The middleware's load is the handler's load. That is what keeps an
// ownership check at one query per request instead of two, and it is the
// reason to prefer this over calling Authorize inside the handler when the
// resource comes from a route parameter.
//
// A load error is returned as-is, so a missing row becomes whatever the
// repository's not-found maps to — usually 404, which is the right answer and
// not something authz should be deciding.
func Owns[R any](ability string, load func(c app.Context) (R, error)) app.Handler {
	return func(c app.Context) error {
		resource, err := load(c)
		if err != nil {
			return err
		}
		if err := Authorize(c, ability, resource); err != nil {
			return err
		}
		c.Set(resourceKey, resource)
		return c.Next()
	}
}

// Resource returns what Owns loaded.
func Resource[R any](c app.Context) (R, bool) {
	value, ok := c.Get(resourceKey).(R)
	return value, ok
}
