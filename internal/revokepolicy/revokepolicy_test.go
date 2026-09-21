package revokepolicy_test

import (
	"testing"

	"github.com/paxanimae/approve-auth/internal/revokepolicy"
)

func strPtr(s string) *string { return &s }

func TestResolve_SessionOverrideWinsOverApplicationAndGlobal(t *testing.T) {
	got := revokepolicy.Resolve(strPtr("revoke"), strPtr("warn"), revokepolicy.ActionOff)
	if got != revokepolicy.ActionRevoke {
		t.Errorf("Resolve = %q, want revoke", got)
	}
}

func TestResolve_ApplicationOverrideWinsOverGlobalWhenSessionUnset(t *testing.T) {
	got := revokepolicy.Resolve(nil, strPtr("flag_for_review"), revokepolicy.ActionOff)
	if got != revokepolicy.ActionFlagForReview {
		t.Errorf("Resolve = %q, want flag_for_review", got)
	}
}

func TestResolve_FallsBackToGlobalWhenBothUnset(t *testing.T) {
	got := revokepolicy.Resolve(nil, nil, revokepolicy.ActionWarn)
	if got != revokepolicy.ActionWarn {
		t.Errorf("Resolve = %q, want warn", got)
	}
}

func TestResolve_InvalidStoredValueFallsThroughRatherThanResolvingBogus(t *testing.T) {
	got := revokepolicy.Resolve(strPtr("not-a-real-action"), strPtr("warn"), revokepolicy.ActionOff)
	if got != revokepolicy.ActionWarn {
		t.Errorf("Resolve = %q, want it to fall through the invalid session override to warn", got)
	}
}

func TestActionMoreSevere_OrdersOffWarnFlagRevoke(t *testing.T) {
	order := []revokepolicy.Action{revokepolicy.ActionOff, revokepolicy.ActionWarn, revokepolicy.ActionFlagForReview, revokepolicy.ActionRevoke}
	for i := 1; i < len(order); i++ {
		if !order[i].MoreSevere(order[i-1]) {
			t.Errorf("%q is not more severe than %q, want strictly increasing severity", order[i], order[i-1])
		}
	}
}

func TestActionValid(t *testing.T) {
	for _, a := range []revokepolicy.Action{revokepolicy.ActionOff, revokepolicy.ActionWarn, revokepolicy.ActionFlagForReview, revokepolicy.ActionRevoke} {
		if !a.Valid() {
			t.Errorf("%q.Valid() = false, want true", a)
		}
	}
	if revokepolicy.Action("bogus").Valid() {
		t.Error(`Action("bogus").Valid() = true, want false`)
	}
}
