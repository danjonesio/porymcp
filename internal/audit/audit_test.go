package audit

import (
	"encoding/json"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	in := json.RawMessage(`{"name":"search","arguments":{"q":"ok"},"token":"sk-live","Authorization":"Bearer x"}`)
	out := Redact(in)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["token"] != "[redacted]" {
		t.Fatalf("token=%v", m["token"])
	}
	if m["Authorization"] != "[redacted]" {
		t.Fatalf("Authorization=%v", m["Authorization"])
	}
	args := m["arguments"].(map[string]any)
	if args["q"] != "ok" {
		t.Fatalf("innocent field redacted: %v", args["q"])
	}
}
