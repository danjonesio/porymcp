// Command echostub is the echo upstream the smoke script registers in CI and
// under make smoke (PORM-213). It serves two doors on one listener: /mcp is a
// Streamable HTTP MCP server with one tool, echo, and /v1/ok plus
// /v1/json401 are an HTTP API door for the relay. It reports what each
// request carried as hashes and counts inside its answers, and on
// /v1/json401 echoes the query value it received, because that body is what
// the relay's redaction is proven on. It holds no secret and logs a verb and
// a route constant only.
//
// It must never be deployed anywhere reachable: it returns a fingerprint of
// whatever credential it is sent. pory_seen is a substring check; a key
// transformed before forwarding (base64 inside a Basic value) is not seen by
// it, and the auth_sha256 match is what proves the Authorization value was
// replaced.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// maxBody bounds every request body the stub reads. A smoke request is a few
// hundred bytes; anything near the cap is not one.
const maxBody = 64 << 10

// sessionID is the constant session the MCP door mints on initialize. No
// method requires it: a group key lists its members with no handshake, and a
// stub that refused that request would be dropped from the group.
const sessionID = "stub-session"

// protocolVersion is what initialize answers. It is the revision PoryMCP
// asks for, so the proxy declares the same value on later requests.
const protocolVersion = "2025-11-25"

func main() {
	addr := flag.String("addr", "127.0.0.1:8098", "listen address; loopback by default, the bridge gateway in CI")
	lifetime := flag.Duration("lifetime", 15*time.Minute, "exit after this long, so a forgotten stub dies")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", serveMCP)
	mux.HandleFunc("/v1/ok", serveOK)
	mux.HandleFunc("/v1/json401", serveJSON401)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logRequest(r, "other", "-")
		http.NotFound(w, r)
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	time.AfterFunc(*lifetime, func() {
		log.Printf("lifetime %s passed, exiting", *lifetime)
		os.Exit(0)
	})
	log.Printf("echostub listening on %s", ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

// logRequest writes the one line a request earns: the verb, a route
// constant and the JSON-RPC method or "-". Never a path, a header, a query
// or a body: the stub's output lands in a public job log.
func logRequest(r *http.Request, route, method string) {
	log.Printf("%s %s %s", r.Method, route, method)
}

// readBody reads at most maxBody bytes. The second value is true when the
// body was over the cap, which the caller answers with 413.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, true
		}
		return body, false
	}
	return body, false
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// proof is the fingerprint of one request: how many Authorization values it
// carried and the digest of the first, which query names it carried, how
// many api_key pieces and the digest of the first, whether any value was
// the client's spoof, and whether a virtual key prefix appeared anywhere.
func proof(r *http.Request, body []byte) map[string]any {
	auth := r.Header.Values("Authorization")
	authSHA := ""
	if len(auth) > 0 {
		authSHA = sha(auth[0])
	}
	q := r.URL.Query()
	names := make([]string, 0, len(q))
	spoof := false
	for name, vals := range q {
		names = append(names, name)
		for _, v := range vals {
			if v == "spoof" {
				spoof = true
			}
		}
	}
	sort.Strings(names)
	creds := q["api_key"]
	credSHA := ""
	if len(creds) > 0 {
		credSHA = sha(creds[0])
	}

	seen := false
	check := func(s string) {
		if strings.Contains(strings.ToLower(s), "pory_") {
			seen = true
		}
	}
	for _, vals := range r.Header {
		for _, v := range vals {
			check(v)
		}
	}
	check(r.Host)
	check(r.RequestURI)
	if u, err := url.PathUnescape(r.RequestURI); err == nil {
		check(u)
	}
	if u, err := url.QueryUnescape(r.RequestURI); err == nil {
		check(u)
	}
	check(string(body))

	return map[string]any{
		"auth_count":  len(auth),
		"auth_sha256": authSHA,
		"query_names": names,
		"page":        q.Get("page"),
		"cred_count":  len(creds),
		"cred_sha256": credSHA,
		"spoof":       spoof,
		"pory_seen":   seen,
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

// writeJSON encodes v as the whole answer. Every body the stub sends goes
// through encoding/json, never through string concatenation.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeRPC writes a JSON-RPC answer with the id as the request carried it.
// An absent id is answered as null, which is what the fixtures do.
func writeRPC(w http.ResponseWriter, status int, id json.RawMessage, result any, rpcErr *rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		out["error"] = rpcErr
	} else {
		out["result"] = result
	}
	writeJSON(w, status, out)
}

// serveMCP is the MCP door. POST carries JSON-RPC; DELETE ends a session;
// other verbs are refused. The method table follows the legacy arm of the
// proxy's test stub: server/discover is unknown, initialize mints a session,
// the notification is a 202, tools/list has one tool and tools/call echo
// returns the message with the request's proof.
func serveMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		logRequest(r, "mcp", "-")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		logRequest(r, "mcp", "-")
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, tooBig := readBody(w, r)
	if tooBig {
		logRequest(r, "mcp", "-")
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		logRequest(r, "mcp", "-")
		writeRPC(w, http.StatusBadRequest, nil, nil, &rpcError{Code: -32700, Message: "Parse error"})
		return
	}
	logRequest(r, "mcp", req.Method)

	switch req.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", sessionID)
		writeRPC(w, http.StatusOK, req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "echostub", "version": "0"},
		}, nil)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		writeRPC(w, http.StatusOK, req.ID, map[string]any{
			"tools": []map[string]any{{
				"name":        "echo",
				"description": "Returns the message with a fingerprint of the request",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{"message": map[string]any{"type": "string"}},
					"required":   []string{"message"},
				},
			}},
		}, nil)
	case "tools/call":
		if req.Params.Name != "echo" {
			writeRPC(w, http.StatusOK, req.ID, nil, &rpcError{Code: -32602, Message: "unknown tool"})
			return
		}
		text, err := json.Marshal(map[string]any{
			"message": req.Params.Arguments["message"],
			"proof":   proof(r, body),
		})
		if err != nil {
			writeRPC(w, http.StatusInternalServerError, req.ID, nil, &rpcError{Code: -32603, Message: "Internal error"})
			return
		}
		writeRPC(w, http.StatusOK, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(text)}},
		}, nil)
	default:
		// server/discover lands here too: a 400 with -32601 is the legacy
		// answer the era probe expects from a server without the method.
		writeRPC(w, http.StatusBadRequest, req.ID, nil, &rpcError{Code: -32601, Message: "Method not found"})
	}
}

// serveOK is the relay's success door and discovery's test_path target. It
// answers 200 for any verb, credential present or not, with the proof.
func serveOK(w http.ResponseWriter, r *http.Request) {
	logRequest(r, "ok", "-")
	body, tooBig := readBody(w, r)
	if tooBig {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proof": proof(r, body)})
}

// serveJSON401 is the relay's error door. It echoes the first api_key value
// under a field named seen, which matches no pattern rule, so a [redacted]
// in the client's copy can only come from the relay's literal pass.
func serveJSON401(w http.ResponseWriter, r *http.Request) {
	logRequest(r, "json401", "-")
	if _, tooBig := readBody(w, r); tooBig {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error": "denied",
		"seen":  r.URL.Query().Get("api_key"),
	})
}
