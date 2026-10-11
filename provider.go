package authz

import "github.com/lemmego/api/app"

// Provider registers the application's rules.
//
//	&authz.Provider{Policies: policies.Register}
//
// Policies is called once, at boot, with the registry — so every rule in the
// application is reachable from one function and the set of them is
// reviewable in one place.
type Provider struct {
	Policies func(r *Registry)
}

func (p *Provider) Provide(a app.App) error {
	registry := NewRegistry()
	if p.Policies != nil {
		p.Policies(registry)
	}
	a.AddService(registry)
	return nil
}
