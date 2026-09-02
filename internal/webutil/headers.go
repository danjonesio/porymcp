package webutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
)

// remoteFontOrigin is the Inter stylesheet host. Drop it from style-src and
// font-src once PORM-43 vendors the font locally.
const remoteFontOrigin = "https://rsms.me"

var srcAttr = regexp.MustCompile(`(?i)(?:^|\s)src\s*=`)

// ContentSecurityPolicy builds the dashboard/API CSP. Inline <script> bodies
// in fsys (every *.html file) are hashed so the policy can omit 'unsafe-inline'
// from script-src. fsys may be nil, in which case script-src is just 'self'.
func ContentSecurityPolicy(fsys fs.FS) string {
	var b strings.Builder
	b.WriteString("default-src 'self'; script-src 'self'")
	for _, h := range InlineScriptHashes(fsys) {
		b.WriteByte(' ')
		b.WriteByte('\'')
		b.WriteString(h)
		b.WriteByte('\'')
	}
	// TODO(PORM-43): drop https://rsms.me from style-src and font-src.
	// style-src-attr is required by Headless UI, which sets a
	// visually-hidden span (and dialog positioning) via style attributes.
	// <style> tags and stylesheets still follow style-src; script-src is
	// unchanged and must stay free of 'unsafe-inline'.
	b.WriteString("; style-src 'self' ")
	b.WriteString(remoteFontOrigin)
	b.WriteString("; style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self' ")
	b.WriteString(remoteFontOrigin)
	b.WriteString("; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	return b.String()
}

// SecurityHeaders sets the v0.1 response headers on every response. It never
// writes Access-Control-* so proxy and dashboard CORS stay intact.
func SecurityHeaders(csp string) func(http.Handler) http.Handler {
	if csp == "" {
		csp = ContentSecurityPolicy(nil)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			next.ServeHTTP(w, r)
		})
	}
}

// InlineScriptHashes returns sorted unique CSP sha256-* tokens for every
// inline script body under fsys. Hashes are computed over the exact bytes
// between the opening <script> tag and the matching </script>.
func InlineScriptHashes(fsys fs.FS) []string {
	if fsys == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var hashes []string
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.EqualFold(path.Ext(p), ".html") {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil
		}
		for _, body := range inlineScriptBodies(data) {
			sum := sha256.Sum256(body)
			h := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			hashes = append(hashes, h)
		}
		return nil
	})
	sort.Strings(hashes)
	return hashes
}

func inlineScriptBodies(html []byte) [][]byte {
	lower := bytes.ToLower(html)
	var out [][]byte
	i := 0
	for i < len(html) {
		start := bytes.Index(lower[i:], []byte("<script"))
		if start < 0 {
			break
		}
		start += i
		tagEnd := bytes.IndexByte(html[start:], '>')
		if tagEnd < 0 {
			break
		}
		tagEnd += start
		open := lower[start:tagEnd]
		rest := lower[tagEnd+1:]
		relClose := bytes.Index(rest, []byte("</script"))
		if relClose < 0 {
			break
		}
		closeStart := tagEnd + 1 + relClose
		if !srcAttr.Match(open) {
			body := html[tagEnd+1 : closeStart]
			copied := make([]byte, len(body))
			copy(copied, body)
			out = append(out, copied)
		}
		gt := bytes.IndexByte(html[closeStart:], '>')
		if gt < 0 {
			break
		}
		i = closeStart + gt + 1
	}
	return out
}

// ScriptSrc is the script-src directive of a CSP, or "" if none is present.
// Tests use it to assert the absence of 'unsafe-inline' without matching that
// token in an unrelated directive.
func ScriptSrc(csp string) string {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "script-src ") || part == "script-src" {
			return part
		}
	}
	return ""
}
