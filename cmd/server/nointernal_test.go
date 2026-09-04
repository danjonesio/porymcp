package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danjonesio/porymcp/internal/crypto"
)

// TestNoInternalReferences is the standing guard behind PORM-122 (plan security
// requirements 3 and 5): the public repository carries no personal, workspace,
// session or key material. No tracked file may name the private workspace's
// URLs or identities, an agent session link, a workstation path, or a sample
// admin key or encryption key in any spelling crypto.ParseKey accepts (hex,
// base64, and the fingerprint the key ring derives). There is no CI yet
// (PORM-10), so this test is the only guard; PORM-10's CI runs it on every
// push. It scans exactly the files git tracks, so untracked local state (a
// developer's .env, a scratch file) cannot fail a clean checkout, and it skips
// itself on a source tree that is not a git checkout (a downloaded archive).
// The local-only working files (the agent workflow and the plan records,
// git-ignored on the public tree) are excluded by path: they are tracked on a
// pre-cut branch and absent from a public clone. String needles are assembled
// from halves so this file stays clean itself; the key needles are derived at
// runtime from the hex alphabet, so no spelling of that key appears here even
// in pieces. The case-insensitive needles are matched against a lowercased
// copy; the case-sensitive ones (a commit trailer, a base64 key) against the
// raw bytes, because lowercasing destroys base64.
func TestNoInternalReferences(t *testing.T) {
	root := repoRoot(t)
	files := trackedFiles(t, root)
	// The sample encryption key is the hex alphabet repeated to 32 bytes.
	keyHex := strings.Repeat("0123456789abcdef", 4)
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	// The raw base64 form is a prefix of the padded one, so one needle covers both.
	keyB64 := base64.RawStdEncoding.EncodeToString(keyBytes)
	keyFP := strings.ToLower(crypto.Fingerprint(keyBytes))
	lowerNeedles := [][]byte{
		[]byte("refresh" + "surplus"),
		[]byte("dan" + "@"),
		[]byte("claude.ai" + "/code"),
		[]byte("linear" + ".app"),
		[]byte("team-" + "refresh"),
		[]byte("origin." + "cursor.com"),
		[]byte("cursor.com" + "/codebase"),
		[]byte("/home/" + "danjones"),
		[]byte("dev-admin-key" + "-change-me"),
		[]byte(keyHex),
		[]byte(keyFP),
	}
	rawNeedles := [][]byte{
		[]byte("Claude-" + "Session"),
		[]byte("Co-Authored" + "-By"),
		[]byte(keyB64),
	}
	for _, file := range files {
		b, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			// An index entry whose working-tree file is gone (mid git-rm, a
			// sparse checkout) is not a leak; do not turn it into one.
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		lower := bytes.ToLower(b)
		for _, n := range lowerNeedles {
			if bytes.Contains(lower, n) {
				t.Errorf("%s: contains internal reference %q", file, n)
			}
		}
		for _, n := range rawNeedles {
			if bytes.Contains(b, n) {
				t.Errorf("%s: contains internal reference %q", file, n)
			}
		}
	}
}
