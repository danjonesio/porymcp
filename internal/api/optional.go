package api

import "encoding/json"

// Optional is a request field that remembers whether it was sent. Set is true
// when the key appeared in the body; Null is true when its value was null;
// Value is the decoded value, or the zero value when absent or null.
//
// encoding/json calls UnmarshalJSON "including when the input is a JSON null"
// (the Unmarshaler contract), which is what makes the third state visible; a
// *T field cannot see it, because null and absent both leave the pointer nil.
// That is the difference between "PATCH {"rate_limit":null}" clearing a limit
// and being silently ignored.
//
// Optional is a request type only. It has no MarshalJSON on purpose and must
// never appear in a struct that is written to a response: its exported fields
// would serialise as {"Set":…,"Null":…,"Value":…}.
type Optional[T any] struct {
	Set, Null bool
	Value     T
}

// UnmarshalJSON records presence and nullness, then decodes a non-null value
// into Value.
func (o *Optional[T]) UnmarshalJSON(b []byte) error {
	// Reassigned on every call, so a duplicate key's last value wins, the same
	// way it does for a plain field.
	o.Set, o.Null = true, string(b) == "null"
	if o.Null {
		var zero T
		o.Value = zero
		return nil
	}
	return json.Unmarshal(b, &o.Value)
}

// Has reports that a value was sent: present and not null.
func (o Optional[T]) Has() bool { return o.Set && !o.Null }
