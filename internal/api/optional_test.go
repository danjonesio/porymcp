package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestOptionalDecode pins the three states Optional carries — absent, null
// and value — through the same decoder entry point decodeBody uses, plus the
// duplicate-key rules (last wins, including a case-variant duplicate, which
// encoding/json binds through its folded-name lookup) and the field-named type
// error the outer decoder adds. PORM-21 security requirement 5: presence
// follows the decoder's own field matching.
func TestOptionalDecode(t *testing.T) {
	type body struct {
		S Optional[string]          `json:"s"`
		I Optional[int]             `json:"i"`
		B Optional[bool]            `json:"b"`
		T Optional[time.Time]       `json:"t"`
		L Optional[[]string]        `json:"l"`
		R Optional[json.RawMessage] `json:"r"`
	}
	decode := func(t *testing.T, raw string) body {
		t.Helper()
		var b body
		if err := json.NewDecoder(strings.NewReader(raw)).Decode(&b); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		return b
	}

	t.Run("absent", func(t *testing.T) {
		b := decode(t, `{}`)
		for name, set := range map[string]bool{"s": b.S.Set, "i": b.I.Set, "b": b.B.Set, "t": b.T.Set, "l": b.L.Set, "r": b.R.Set} {
			if set {
				t.Errorf("%s: Set on an absent key", name)
			}
		}
		if b.S.Has() {
			t.Error("Has() on an absent key")
		}
	})

	t.Run("null", func(t *testing.T) {
		b := decode(t, `{"s":null,"i":null,"b":null,"t":null,"l":null,"r":null}`)
		for _, c := range []struct {
			name      string
			set, null bool
		}{
			{"s", b.S.Set, b.S.Null}, {"i", b.I.Set, b.I.Null}, {"b", b.B.Set, b.B.Null},
			{"t", b.T.Set, b.T.Null}, {"l", b.L.Set, b.L.Null}, {"r", b.R.Set, b.R.Null},
		} {
			if !c.set || !c.null {
				t.Errorf("%s: want Set && Null, got Set=%v Null=%v", c.name, c.set, c.null)
			}
		}
		if b.S.Value != "" || b.I.Value != 0 || b.B.Value || !b.T.Value.IsZero() || b.L.Value != nil || b.R.Value != nil {
			t.Errorf("null did not leave zero values: %+v", b)
		}
		if b.S.Has() {
			t.Error("Has() on null")
		}
	})

	t.Run("value", func(t *testing.T) {
		b := decode(t, `{"s":"x","i":7,"b":true,"t":"2026-01-02T03:04:05Z","l":[],"r":{"k":1}}`)
		if !b.S.Has() || b.S.Value != "x" {
			t.Errorf("s: %+v", b.S)
		}
		if !b.I.Has() || b.I.Value != 7 {
			t.Errorf("i: %+v", b.I)
		}
		if !b.B.Has() || !b.B.Value {
			t.Errorf("b: %+v", b.B)
		}
		if want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC); !b.T.Has() || !b.T.Value.Equal(want) {
			t.Errorf("t: %+v", b.T)
		}
		// [] must be a non-nil empty slice: the handlers distinguish a nil
		// slice (absent, or null before normalisation) from an empty one.
		if !b.L.Has() || b.L.Value == nil || len(b.L.Value) != 0 {
			t.Errorf("l: [] must decode to a non-nil empty slice, got %#v", b.L)
		}
		if !b.R.Has() || string(b.R.Value) != `{"k":1}` {
			t.Errorf("r: %+v", b.R)
		}
	})

	t.Run("duplicate key, last wins", func(t *testing.T) {
		b := decode(t, `{"i":null,"i":5}`)
		if !b.I.Set || b.I.Null || b.I.Value != 5 {
			t.Errorf("want Set && !Null && Value==5, got %+v", b.I)
		}
	})

	t.Run("case-variant duplicate, last wins", func(t *testing.T) {
		// "I" reaches the same field through encoding/json's folded-name
		// lookup, so presence cannot be fooled by a case variant.
		b := decode(t, `{"i":5,"I":null}`)
		if !b.I.Set || !b.I.Null || b.I.Value != 0 {
			t.Errorf("want Set && Null && Value==0, got %+v", b.I)
		}
	})

	t.Run("type error names the field", func(t *testing.T) {
		var b body
		err := json.NewDecoder(strings.NewReader(`{"i":"x"}`)).Decode(&b)
		if err == nil {
			t.Fatal("expected a type error")
		}
		for _, want := range []string{".i", "of type int"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err.Error(), want)
			}
		}
	})
}
