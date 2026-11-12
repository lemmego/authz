package authz

import (
	"embed"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"strings"
	"sync"

	"github.com/lemmego/api/app"
)

// The keys the built-in rules deny with.
//
// Namespaced with "authz::" because that is how lemmego/i18n addresses a
// module's own catalogue mounted alongside an application's, and spelled out
// as constants so a typo in one is a compile error rather than a sentence
// nobody notices is missing.
//
// Only the five reasons a *reader* sees are keyed. The three in authz.go that
// name an ability — "no rule is registered for %q" and the two about a
// resource — stay English on purpose: they are programming errors, and
// translating one would put a bug behind a language.
const (
	KeyUnauthenticated  = "authz::errors.unauthenticated"
	KeyForbidden        = "authz::errors.forbidden"
	KeyOwnershipUnknown = "authz::errors.ownership_unknown"
	KeyNotOwner         = "authz::errors.not_owner"
	KeyNoRuleAllowed    = "authz::errors.no_rule_allowed"
)

//go:embed catalog
var catalogFS embed.FS

// Catalogue returns this module's own messages, laid out the way an
// application's catalogue is: en/errors.json and so on.
//
// Mount it so the keys resolve, and so a translator can add a language:
//
//	cat.Mount("authz", authz.Catalogue(), ".")
//
// Unmounted, nothing breaks — resolution falls through to the English below,
// which is what a project that never registers a translator gets.
func Catalogue() fs.FS {
	sub, err := fs.Sub(catalogFS, "catalog")
	if err != nil {
		// Embedded at compile time, so this cannot happen.
		panic("authz: " + err.Error())
	}
	return sub
}

// builtinMessages is the English floor.
//
// The same shape api/app uses for its validation messages, and for the same
// reason: a module that keyed its messages and then needed a translator
// registered to say anything would have made every project depend on i18n to
// get a sentence out of a 403. Parsed from the embedded file rather than
// written twice, so the floor and the publishable cannot drift.
var builtinMessages = sync.OnceValue(func() map[string]string {
	data, err := fs.ReadFile(Catalogue(), "en/errors.json")
	if err != nil {
		panic("authz: " + err.Error())
	}
	var messages map[string]string
	if err := json.Unmarshal(data, &messages); err != nil {
		panic("authz: " + err.Error())
	}
	out := make(map[string]string, len(messages))
	for key, text := range messages {
		out["authz::errors."+key] = text
	}
	return out
})

// BuiltinMessages returns a copy of the English this module falls back to.
func BuiltinMessages() map[string]string { return maps.Clone(builtinMessages()) }

// resolve turns a denial's reason into a sentence somebody can read.
//
// A reason is looked up as a key first, then against the English floor, then
// used verbatim. The verbatim step is what keeps an application's own rules
// working unchanged: a policy that denies with "you cannot edit a published
// launch" keeps saying exactly that, and opts into translation by returning a
// key instead. The ambiguity is not real in practice — a key is a dotted
// lowercase identifier and a message is a sentence — and if it ever bites, an
// explicit-key form is purely additive.
func resolve(c app.Context, reason string) string {
	if reason == "" {
		return ""
	}
	if t := c.T(); t != nil && t.Has(reason) {
		return t.Get(reason)
	}
	if text, ok := builtinMessages()[reason]; ok {
		return text
	}
	return reason
}

// TagCatalogue selects this module's publishable messages.
//
// Namespaced rather than a bare "authz", because --tags is a hard selector
// that errors on an unknown tag, so two providers sharing a generic name are
// indistinguishable on the command line.
const TagCatalogue = "authz-i18n"

// AddPublishables offers this module's English for editing.
//
// `lemmego run publish --tags=authz-i18n` writes it to
// resources/lang/vendor/authz/en/errors.json, which is where an application's
// catalogue looks for an override of a mounted module — so editing the file is
// the whole mechanism, and api/app/publish.go already refuses to overwrite one
// somebody has changed.
func (p *Provider) AddPublishables() []*app.Publishable {
	data, err := fs.ReadFile(Catalogue(), "en/errors.json")
	if err != nil {
		return nil
	}
	return []*app.Publishable{{
		FilePath: langPath() + "/vendor/authz/en/errors.json",
		Content:  data,
		Tag:      TagCatalogue,
	}}
}

// langPath is where the application keeps its catalogue.
//
// Read directly rather than through config.MustEnv, which treats a variable
// that is present and empty as a decision — so a stray "I18N_PATH=" line in a
// production .env would publish to "/vendor/authz/...", at the filesystem
// root. That helper's shape has invited this in api/logger and in mail
// already.
func langPath() string {
	if value, ok := os.LookupEnv("I18N_PATH"); ok {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return strings.TrimRight(trimmed, "/")
		}
	}
	return "resources/lang"
}

// A note on the English in catalog/en/errors.json: it is byte-identical to
// the strings these rules returned before they were keyed, lowercase and
// terse as they were. Rewriting them while moving them would have changed
// what every consumer's tests and docs assert, for a reading improvement
// nobody asked for — and the tests here caught exactly that on the first
// attempt. An application that wants different wording publishes the file and
// changes it, which is the whole point of publishing it.
