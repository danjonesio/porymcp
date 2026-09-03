package mcpclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/netcasklabs/porymcp/internal/models"
)

// ErrNoCredential reports that an auth type other than none has nothing to
// send: the value is empty, is not an auth_config, or carries no field its
// auth type writes. ApplyAuth writes no credential in that case, and a caller
// that dialled anyway would hand the upstream an unauthenticated request and
// read its 401 as a bad token, the silent failure PORM-52 removes. The proxy
// and the discover gate refuse before the request is built; this error is how
// they know to.
var ErrNoCredential = errors.New("credential is empty or not valid for its auth type")

// ApplyAuth writes real credentials onto the outbound request and strips the
// inbound virtual-key Authorization so it never leaks upstream. It returns
// ErrNoCredential (and writes nothing) when authType needs a credential and
// raw does not supply one; auth_type none always succeeds and writes nothing.
func ApplyAuth(req *http.Request, authType string, raw json.RawMessage) error {
	req.Header.Del("Authorization")
	req.Header.Del("X-Api-Key")
	req.Header.Del("X-API-Key")

	h, err := headersFor(authType, raw)
	if err != nil {
		return err
	}
	for name, vals := range h {
		req.Header[name] = vals
	}
	return nil
}

// CheckCredential is ApplyAuth's verdict without a request: nil when ApplyAuth
// would write a credential (or authType is none), ErrNoCredential otherwise.
// It is the one predicate the proxy, the discover gate and auth_status share.
func CheckCredential(authType string, raw json.RawMessage) error {
	_, err := headersFor(authType, raw)
	return err
}

// headersFor is the one place that decides what a credential writes. It builds
// an http.Header (whose Set canonicalises names) in the same order ApplyAuth
// always wrote them, so a custom auth_config whose "header" repeats a key in
// "headers" still resolves to the later Set, deterministically, rather than to
// whichever of two map keys iterated last.
//
// ErrNoCredential iff authType is not none and: raw is empty, raw does not
// unmarshal (a partially decodable value counts as not decoded), or the
// branch for authType would write no header: bearer with no token; header or
// api_key with no value; custom with no headers and no header/value pair. An
// empty value inside custom "headers" still counts as written, as it always
// has. An unknown auth type writes nothing and is ErrNoCredential.
func headersFor(authType string, raw json.RawMessage) (http.Header, error) {
	h := http.Header{}
	switch authType {
	case models.AuthNone, "":
		return h, nil
	}
	if len(raw) == 0 {
		return nil, ErrNoCredential
	}
	var cfg models.AuthConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, ErrNoCredential
	}

	switch authType {
	case models.AuthBearer:
		token := cfg.Token
		if token == "" {
			token = strings.TrimPrefix(cfg.Value, "Bearer ")
			token = strings.TrimSpace(token)
		}
		if token != "" {
			h.Set("Authorization", "Bearer "+token)
		}
	case models.AuthHeader:
		if cfg.Header != "" && cfg.Value != "" {
			h.Set(cfg.Header, cfg.Value)
		}
	case models.AuthAPIKey:
		header := cfg.Header
		if header == "" {
			header = "X-API-Key"
		}
		val := cfg.Value
		if val == "" {
			val = cfg.Token
		}
		if val != "" {
			h.Set(header, val)
		}
	case models.AuthCustom:
		for k, v := range cfg.Headers {
			h.Set(k, v)
		}
		if cfg.Header != "" && cfg.Value != "" {
			h.Set(cfg.Header, cfg.Value)
		}
	}
	if len(h) == 0 {
		return nil, ErrNoCredential
	}
	return h, nil
}
