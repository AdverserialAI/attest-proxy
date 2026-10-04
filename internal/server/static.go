package server

import (
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// hostOnly lowercases and strips any port from a Host header value.
func hostOnly(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// isAPIRoute reports whether a path belongs to the API surface (which the
// chat vhost must keep routing to the API handlers, so the UI can call the
// API through the same public base URL).
func isAPIRoute(p string) bool {
	return p == "/attestation" ||
		p == "/healthz" ||
		strings.HasPrefix(p, "/.well-known/") ||
		strings.HasPrefix(p, "/v1/")
}

// hostRouter routes requests for CHAT_HOST to the static SPA (everything
// except API routes); all other hosts go straight to the API. When the vhost
// is not configured it is a no-op.
func (s *Server) hostRouter(api http.Handler) http.Handler {
	if s.cfg.ChatHost == "" || s.cfg.ChatDocroot == "" {
		return api
	}
	static := &staticHandler{root: s.cfg.ChatDocroot}
	chatHost := strings.ToLower(s.cfg.ChatHost)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostOnly(r.Host) == chatHost && !isAPIRoute(r.URL.Path) {
			static.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
}

// staticHandler serves the browser chat SPA from a docroot: real files when
// they exist, index.html as SPA fallback for unknown non-asset paths.
// Hash-named build assets under /_app/ get long-cache headers; index.html
// gets no-cache so deploys propagate.
type staticHandler struct {
	root string
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Clean against a rooted path so ".." cannot escape the docroot.
	p := path.Clean("/" + r.URL.Path)
	full := filepath.Join(h.root, filepath.FromSlash(p))

	if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
		h.serveFile(w, r, p, full)
		return
	}
	if path.Ext(p) != "" {
		// Looks like an asset but does not exist — a real 404, not the SPA.
		http.NotFound(w, r)
		return
	}
	// SPA fallback.
	h.serveFile(w, r, "/index.html", filepath.Join(h.root, "index.html"))
}

func (h *staticHandler) serveFile(w http.ResponseWriter, r *http.Request, urlPath, full string) {
	f, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasPrefix(urlPath, "/_app/"):
		// Hash-named, immutable build output.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case path.Base(urlPath) == "index.html":
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}
