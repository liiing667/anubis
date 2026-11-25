package lib

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/lib/policy"
)

func TestValidateCookieDomain(t *testing.T) {
	for _, tt := range []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{name: "empty", domain: ""},
		{name: "registrable domain", domain: "techaro.lol"},
		{name: "uppercase registrable domain", domain: "TECHARO.LOL"},
		{name: "controlled subdomain", domain: "anubis.techaro.lol"},
		{name: "leading dot", domain: ".techaro.lol"},
		{name: "ipv4", domain: "127.0.0.1"},
		{name: "localhost", domain: "localhost"},
		{name: "private suffix tenant", domain: "tenant.github.io"},
		{name: "icann public suffix", domain: "com", wantErr: true},
		{name: "uppercase icann public suffix", domain: "COM", wantErr: true},
		{name: "multi-label icann public suffix", domain: "co.uk", wantErr: true},
		{name: "leading dot public suffix", domain: ".co.uk", wantErr: true},
		{name: "private public suffix", domain: "github.io", wantErr: true},
		{name: "trailing dot", domain: "techaro.lol.", wantErr: true},
		{name: "port", domain: "techaro.lol:443", wantErr: true},
		{name: "wildcard", domain: "*.techaro.lol", wantErr: true},
		{name: "ipv6", domain: "::1", wantErr: true},
		{name: "empty label", domain: "foo..techaro.lol", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCookieDomain(tt.domain)
			if tt.wantErr && !errors.Is(err, ErrInvalidCookieDomain) {
				t.Errorf("wanted invalid cookie domain error, got: %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("wanted valid cookie domain, got: %v", err)
			}
		})
	}
}

func TestNewRejectsPublicSuffixCookieDomain(t *testing.T) {
	if _, err := New(Options{CookieDomain: "co.uk"}); !errors.Is(err, ErrInvalidCookieDomain) {
		t.Fatalf("wanted invalid cookie domain error, got: %v", err)
	}
}

func TestCookieDomainDoesNotWidenToPublicSuffix(t *testing.T) {
	srv := &Server{opts: Options{CookieDomain: "co.uk"}}
	if got := srv.cookieDomain("tenant.example.co.uk"); got != "" {
		t.Errorf("wanted host-only cookie domain, got: %q", got)
	}
}

func TestSetCookie(t *testing.T) {
	for _, tt := range []struct {
		name       string
		host       string
		cookieName string
		options    Options
	}{
		{
			name:       "basic",
			options:    Options{},
			host:       "",
			cookieName: anubis.CookieName,
		},
		{
			name:       "domain techaro.lol",
			options:    Options{CookieDomain: "techaro.lol"},
			host:       "",
			cookieName: anubis.CookieName,
		},
		{
			name:       "dynamic cookie domain",
			options:    Options{CookieDynamicDomain: true},
			host:       "techaro.lol",
			cookieName: anubis.CookieName,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := spawnAnubis(t, tt.options)
			rw := httptest.NewRecorder()

			tt.cookieName = srv.cookieName(tt.cookieName)

			srv.SetCookie(rw, CookieOpts{Value: "test", Host: tt.host})

			resp := rw.Result()
			cookies := resp.Cookies()

			ckie := cookies[0]

			if ckie.Name != tt.cookieName {
				t.Errorf("wanted cookie named %q, got cookie named %q", tt.cookieName, ckie.Name)
			}
		})
	}
}

func TestClearCookie(t *testing.T) {
	srv := spawnAnubis(t, Options{})
	rw := httptest.NewRecorder()

	srv.ClearCookie(rw, CookieOpts{Host: "localhost"})

	resp := rw.Result()

	cookies := resp.Cookies()

	if len(cookies) != 1 {
		t.Errorf("wanted 1 cookie, got %d cookies", len(cookies))
	}

	ckie := cookies[0]

	if want := srv.cookieName(anubis.CookieName); ckie.Name != want {
		t.Errorf("wanted cookie named %q, got cookie named %q", want, ckie.Name)
	}

	if ckie.MaxAge != -1 {
		t.Errorf("wanted cookie max age of -1, got: %d", ckie.MaxAge)
	}
}

func TestClearCookieWithDomain(t *testing.T) {
	srv := spawnAnubis(t, Options{CookieDomain: "techaro.lol"})
	rw := httptest.NewRecorder()

	srv.ClearCookie(rw, CookieOpts{Host: "localhost"})

	resp := rw.Result()

	cookies := resp.Cookies()

	if len(cookies) != 1 {
		t.Errorf("wanted 1 cookie, got %d cookies", len(cookies))
	}

	ckie := cookies[0]

	if want := srv.cookieName(anubis.CookieName); ckie.Name != want {
		t.Errorf("wanted cookie named %q, got cookie named %q", want, ckie.Name)
	}

	if ckie.MaxAge != -1 {
		t.Errorf("wanted cookie max age of -1, got: %d", ckie.MaxAge)
	}
}

func TestClearCookieWithDynamicDomain(t *testing.T) {
	srv := spawnAnubis(t, Options{CookieDynamicDomain: true})
	rw := httptest.NewRecorder()

	srv.ClearCookie(rw, CookieOpts{Host: "subdomain.xeiaso.net"})

	resp := rw.Result()

	cookies := resp.Cookies()

	if len(cookies) != 1 {
		t.Errorf("wanted 1 cookie, got %d cookies", len(cookies))
	}

	ckie := cookies[0]

	if want := srv.cookieName(anubis.CookieName); ckie.Name != want {
		t.Errorf("wanted cookie named %q, got cookie named %q", want, ckie.Name)
	}

	if ckie.Domain != "xeiaso.net" {
		t.Errorf("wanted cookie domain %q, got cookie domain %q", "xeiaso.net", ckie.Domain)
	}

	if ckie.MaxAge != -1 {
		t.Errorf("wanted cookie max age of -1, got: %d", ckie.MaxAge)
	}
}

func TestRenderIndexRedirect(t *testing.T) {
	s := &Server{
		opts: Options{
			PublicUrl: "https://anubis.example.com",
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/foo")

	rr := httptest.NewRecorder()
	s.RenderIndex(rr, req, policy.CheckResult{}, nil, true)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status %d, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
	location := rr.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse location URL %q: %v", location, err)
	}

	scheme := "https"
	if parsedURL.Scheme != scheme {
		t.Errorf("expected scheme to be %q, got %q", scheme, parsedURL.Scheme)
	}

	host := "anubis.example.com"
	if parsedURL.Host != host {
		t.Errorf("expected url to be %q, got %q", host, parsedURL.Host)
	}

	redir := parsedURL.Query().Get("redir")
	expectedRedir := "https://example.com/foo"
	if redir != expectedRedir {
		t.Errorf("expected redir param to be %q, got %q", expectedRedir, redir)
	}
}

func TestRenderIndexUnauthorized(t *testing.T) {
	s := &Server{
		opts: Options{
			PublicUrl: "",
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	s.RenderIndex(rr, req, policy.CheckResult{}, nil, true)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if body := rr.Body.String(); body != "Authorization required" {
		t.Errorf("expected body %q, got %q", "Authorization required", body)
	}
}

func TestNoCacheOnError(t *testing.T) {
	pol := loadPolicies(t, "testdata/useragent.yaml", 0)
	srv := spawnAnubis(t, Options{Policy: pol})
	ts := httptest.NewServer(internal.RemoteXRealIP(true, "tcp", srv))
	defer ts.Close()

	for userAgent, expectedCacheControl := range map[string]string{
		"DENY":      "no-store",
		"CHALLENGE": "no-store",
		"ALLOW":     "no-store",
	} {
		t.Run(userAgent, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("User-Agent", userAgent)

			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if resp.Header.Get("Cache-Control") != expectedCacheControl {
				t.Errorf("wanted Cache-Control header %q, got %q", expectedCacheControl, resp.Header.Get("Cache-Control"))
			}
		})
	}
}

func TestRejectsHostlessRedirect(t *testing.T) {
	pol := loadPolicies(t, "testdata/useragent.yaml", 0)
	srv := spawnAnubis(t, Options{Policy: pol, RedirectDomains: []string{"allowed.example"}})
	req := httptest.NewRequest(http.MethodGet, "https://anubis.example/.within.website/?redir=%2f%2fevil.example%2fphish", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTPNext(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected hostless redirect to be rejected, got HTTP %d body %q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("expected no Location header on rejected redirect, got %q", got)
	}
}
