package authz

import (
	"io/fs"
	"strings"
	"testing"
)

// TestTheFloorHoldsEveryKeyTheRulesDenyWith.
//
// A keyed reason with nothing behind it would reach a reader as
// "authz::errors.not_owner" in a 403 body — which is why this module carries
// its own English rather than requiring a translator to say anything at all.
func TestTheFloorHoldsEveryKeyTheRulesDenyWith(t *testing.T) {
	floor := BuiltinMessages()
	for _, key := range []string{
		KeyUnauthenticated, KeyForbidden, KeyOwnershipUnknown,
		KeyNotOwner, KeyNoRuleAllowed,
	} {
		text, ok := floor[key]
		if !ok {
			t.Errorf("%s has no English, so a project without a translator would "+
				"show the key", key)
			continue
		}
		if strings.Contains(text, "::") || strings.Contains(text, "authz.") {
			t.Errorf("%s = %q, which is a key and not a sentence", key, text)
		}
	}
	if len(floor) != 5 {
		t.Errorf("the floor has %d messages; every key the rules use should be "+
			"here and nothing else", len(floor))
	}
}

// TestTheFloorIsCopiedNotShared, so a caller cannot edit every future reader's
// messages.
func TestTheFloorIsCopiedNotShared(t *testing.T) {
	BuiltinMessages()[KeyForbidden] = "mutated"
	if BuiltinMessages()[KeyForbidden] == "mutated" {
		t.Error("BuiltinMessages hands out the live map")
	}
}

// TestTheCatalogueIsLaidOutTheWayAnApplicationsIs, because it is mounted
// alongside one and read by the same loader.
func TestTheCatalogueIsLaidOutTheWayAnApplicationsIs(t *testing.T) {
	entries, err := fs.ReadDir(Catalogue(), "en")
	if err != nil {
		t.Fatalf("the catalogue has no en directory: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 1 || names[0] != "errors.json" {
		t.Errorf("en/ holds %v, want exactly errors.json — the group name is half "+
			"the key", names)
	}
}

// TestThePublishableLandsWhereAnOverrideIsRead.
//
// lemmego/i18n looks for an application's override of a mounted module at
// <lang>/vendor/<namespace>/<locale>/<group>.json, so publishing anywhere else
// writes a file that nothing reads — which looks exactly like a translation
// that did not take effect.
func TestThePublishableLandsWhereAnOverrideIsRead(t *testing.T) {
	published := (&Provider{}).AddPublishables()
	if len(published) != 1 {
		t.Fatalf("published %d files, want 1", len(published))
	}

	item := published[0]
	if want := "resources/lang/vendor/authz/en/errors.json"; item.FilePath != want {
		t.Errorf("FilePath = %q, want %q", item.FilePath, want)
	}
	if item.Tag != TagCatalogue {
		t.Errorf("Tag = %q, want %q", item.Tag, TagCatalogue)
	}
	if !strings.HasPrefix(TagCatalogue, "authz") {
		t.Errorf("the tag %q is not namespaced; --tags is a hard selector, so a "+
			"generic name collides with another provider's", TagCatalogue)
	}
	if !strings.Contains(string(item.Content), "you do not own this") {
		t.Error("the published file does not hold the English it exists to let " +
			"somebody edit")
	}
}

// TestADeveloperErrorIsNotTranslated.
//
// "no rule is registered for %q" means an ability was misspelled or a rule was
// deleted in a refactor. Putting it behind a catalogue would hide a bug behind
// a language, and the reader it is addressed to is us.
func TestADeveloperErrorIsNotTranslated(t *testing.T) {
	floor := BuiltinMessages()
	for key, text := range floor {
		for _, developer := range []string{"no rule is registered", "takes no resource", "needs a resource"} {
			if strings.Contains(text, developer) {
				t.Errorf("%s = %q, which is a programming error and should stay "+
					"English", key, text)
			}
		}
	}
}
