package webutil

import (
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// SPA serves a Next.js static export and falls back to index.html for client routes.
type SPA struct {
	FS   fs.FS
	Root string // optional disk root, used only for logs
}

func NewSPA(root string) *SPA {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil
	}
	return &SPA{FS: os.DirFS(root), Root: root}
}

func FromFS(fsys fs.FS) *SPA {
	if fsys == nil {
		return nil
	}
	return &SPA{FS: fsys, Root: "embedded"}
}

func (s *SPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.FS == nil {
		http.NotFound(w, r)
		return
	}
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" || p == "." {
		p = "index.html"
	}
	f, err := s.FS.Open(p)
	if err != nil {
		f, err = s.FS.Open(path.Join(p, "index.html"))
	} else if st, statErr := f.Stat(); statErr == nil && st.IsDir() {
		_ = f.Close()
		f, err = s.FS.Open(path.Join(p, "index.html"))
	}
	if err != nil {
		f, err = s.FS.Open("index.html")
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		http.NotFound(w, r)
		return
	}
	mod := st.ModTime()
	if mod.IsZero() {
		mod = time.Now()
	}
	http.ServeContent(w, r, st.Name(), mod, rs)
}
