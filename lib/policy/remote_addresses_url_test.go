package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TecharoHQ/anubis/internal/iplist"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/gaissmai/bart"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func newTestRemoteAddressesURLChecker(rawURL string) *RemoteAddressesURLChecker {
	parsedURL, _ := url.Parse(rawURL)
	return &RemoteAddressesURLChecker{
		url:             rawURL,
		parsedURL:       parsedURL,
		logger:          discardLogger(),
		client:          &http.Client{Timeout: 5 * time.Second},
		prefixTable:     new(bart.Lite),
		refreshInterval: 24 * time.Hour,
		retryInterval:   15 * time.Minute,
		maxRetries:      5,
		stopped:         make(chan struct{}),
	}
}

func checkIP(t *testing.T, c *RemoteAddressesURLChecker, ip string) bool {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("can't make request: %v", err)
	}
	r.Header.Set("X-Real-IP", ip)
	ok, err := c.Check(r)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return ok
}

func jsonHandler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

// scriptedTransport replies from in-memory handlers without binding a socket,
// which keeps the fetch/refresh behavior testable in restricted environments.
type scriptedTransport struct {
	t       *testing.T
	handler http.Handler
}

func (s *scriptedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.t.Helper()
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// newCheckerWithHandler builds a checker backed by a scripted transport so the
// test never needs a listening socket. The checker URL stays https so the
// redirect/scheme security gate is exercised with a trusted origin.
func newCheckerWithHandler(t *testing.T, handler http.Handler) *RemoteAddressesURLChecker {
	t.Helper()
	c := newTestRemoteAddressesURLChecker("https://example.invalid/bots.json")
	c.client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: remoteAddressesRedirect, Transport: &scriptedTransport{t: t, handler: handler}}
	return c
}

const samplePrefixList = `{
	"creationTime": "2025-01-02T03:04:05.000000",
	"prefixes": [
		{"ipv4Prefix": "20.42.10.176/28"},
		{"ipv6Prefix": "2001:db8::/32"}
	]
}`

func TestRemoteAddressesURLChecker_emptyBeforeFetch(t *testing.T) {
	c := newTestRemoteAddressesURLChecker("http://127.0.0.1:1/missing.json")
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("empty list should not match any IP")
	}
	if checkIP(t, c, "1.1.1.1") {
		t.Fatal("empty list should not match any IP")
	}
}

func TestRemoteAddressesURLChecker_successfulFetch(t *testing.T) {
	var gotUA string
	c := newCheckerWithHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, samplePrefixList)
	}))
	delay := c.refreshOnce(t.Context())
	if delay != c.refreshInterval {
		t.Fatalf("delay = %v, want %v", delay, c.refreshInterval)
	}
	wantUA := "TecharoHQ-Anubis/" + anubis.Version
	if gotUA != wantUA {
		t.Fatalf("User-Agent = %q, want %q", gotUA, wantUA)
	}
	if c.consecutiveFail != 0 {
		t.Fatalf("consecutiveFail = %d, want 0", c.consecutiveFail)
	}
	if c.rebuildCount != 1 {
		t.Fatalf("rebuildCount = %d, want 1", c.rebuildCount)
	}
	if c.Hash() == "" {
		t.Fatal("hash should be non-empty after a successful fetch")
	}

	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected 20.42.10.176 to match")
	}
	if !checkIP(t, c, "20.42.10.191") {
		t.Fatal("expected 20.42.10.191 (end of /28) to match")
	}
	if checkIP(t, c, "20.42.10.192") {
		t.Fatal("expected 20.42.10.192 to be outside the prefix")
	}
	if !checkIP(t, c, "2001:db8::1") {
		t.Fatal("expected IPv6 prefix to match")
	}
	if checkIP(t, c, "1.1.1.1") {
		t.Fatal("expected unrelated IPv4 not to match")
	}
}

func TestRemoteAddressesURLChecker_http5xx(t *testing.T) {
	c := newCheckerWithHandler(t, jsonHandler(http.StatusInternalServerError, "nope"))
	c.cycleStart = time.Now()

	delay := c.refreshOnce(t.Context())
	if delay != c.retryInterval {
		t.Fatalf("delay = %v, want retry interval %v", delay, c.retryInterval)
	}
	if c.consecutiveFail != 1 {
		t.Fatalf("consecutiveFail = %d, want 1", c.consecutiveFail)
	}
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("failed fetch must not populate the list")
	}
}

func TestRemoteAddressesURLChecker_http5xxGivesUpAfterMaxRetries(t *testing.T) {
	c := newCheckerWithHandler(t, jsonHandler(http.StatusBadGateway, "nope"))
	c.cycleStart = time.Now()
	c.consecutiveFail = 4

	delay := c.refreshOnce(t.Context())
	if delay < 23*time.Hour || delay > 24*time.Hour {
		t.Fatalf("delay = %v, want remainder of 24h window", delay)
	}
	if c.consecutiveFail != 0 {
		t.Fatalf("consecutiveFail = %d, want 0 after giving up", c.consecutiveFail)
	}
}

func TestRemoteAddressesURLChecker_http5xxKeepsExistingList(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)

	c := newCheckerWithHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			_, _ = io.WriteString(w, samplePrefixList)
		}
	}))
	if delay := c.refreshOnce(t.Context()); delay != c.refreshInterval {
		t.Fatalf("initial fetch delay = %v, want %v", delay, c.refreshInterval)
	}
	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected initial fetch to populate the list")
	}

	status.Store(http.StatusInternalServerError)
	c.cycleStart = time.Now()
	if delay := c.refreshOnce(t.Context()); delay != c.retryInterval {
		t.Fatalf("5xx delay = %v, want %v", delay, c.retryInterval)
	}
	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("existing list must be kept after a 5xx response")
	}
}

func TestRemoteAddressesURLChecker_http4xx(t *testing.T) {
	c := newCheckerWithHandler(t, jsonHandler(http.StatusNotFound, "missing"))
	c.cycleStart = time.Now()

	delay := c.refreshOnce(t.Context())
	if delay < 23*time.Hour || delay > 24*time.Hour {
		t.Fatalf("delay = %v, want remainder of 24h window", delay)
	}
	if c.consecutiveFail != 0 {
		t.Fatalf("consecutiveFail = %d, want 0 (4xx does not retry)", c.consecutiveFail)
	}
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("4xx fetch must not populate the list")
	}
}

func TestRemoteAddressesURLChecker_invalidJSON(t *testing.T) {
	c := newCheckerWithHandler(t, jsonHandler(http.StatusOK, `{not json`))
	c.cycleStart = time.Now()

	delay := c.refreshOnce(t.Context())
	if delay < 23*time.Hour || delay > 24*time.Hour {
		t.Fatalf("delay = %v, want remainder of 24h window", delay)
	}
	if c.rebuildCount != 0 {
		t.Fatalf("rebuildCount = %d, want 0", c.rebuildCount)
	}
}

func TestRemoteAddressesURLChecker_invalidCIDR(t *testing.T) {
	body := `{"creationTime": "t", "prefixes": [{"ipv4Prefix": "not-a-cidr"}]}`
	c := newCheckerWithHandler(t, jsonHandler(http.StatusOK, body))
	c.cycleStart = time.Now()

	delay := c.refreshOnce(t.Context())
	if delay < 23*time.Hour || delay > 24*time.Hour {
		t.Fatalf("delay = %v, want remainder of 24h window", delay)
	}
	if c.rebuildCount != 0 {
		t.Fatalf("rebuildCount = %d, want 0", c.rebuildCount)
	}
}

func TestRemoteAddressesURLChecker_unchangedCreationTime(t *testing.T) {
	c := newCheckerWithHandler(t, jsonHandler(http.StatusOK, samplePrefixList))
	if delay := c.refreshOnce(t.Context()); delay != c.refreshInterval {
		t.Fatalf("first fetch delay = %v, want %v", delay, c.refreshInterval)
	}
	hash := c.Hash()
	if c.rebuildCount != 1 {
		t.Fatalf("rebuildCount = %d, want 1", c.rebuildCount)
	}

	if delay := c.refreshOnce(t.Context()); delay != c.refreshInterval {
		t.Fatalf("second fetch delay = %v, want %v", delay, c.refreshInterval)
	}
	if c.rebuildCount != 1 {
		t.Fatalf("rebuildCount = %d, want 1 (creationTime unchanged)", c.rebuildCount)
	}
	if c.Hash() != hash {
		t.Fatal("hash should be unchanged when creationTime matches")
	}
}

func TestRemoteAddressesURLChecker_creationTimeChangeRebuilds(t *testing.T) {
	var body atomic.Value
	body.Store(samplePrefixList)

	c := newCheckerWithHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	c.refreshOnce(t.Context())

	body.Store(`{
		"creationTime": "2026-09-18T00:00:00.000000",
		"prefixes": [{"ipv4Prefix": "1.1.1.1/32"}]
	}`)
	c.refreshOnce(t.Context())

	if c.rebuildCount != 2 {
		t.Fatalf("rebuildCount = %d, want 2", c.rebuildCount)
	}
	if !checkIP(t, c, "1.1.1.1") {
		t.Fatal("expected rebuilt list to contain 1.1.1.1")
	}
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected old prefixes to be replaced, not merged")
	}
}

func TestNewRemoteAddressesURLChecker_invalidURL(t *testing.T) {
	t.Parallel()

	cases := []string{
		"not a url",
		"",
		"http://example.com/bots.json", // plaintext HTTP is not a trusted source
		"HTTP://example.com/bots.json", // scheme casing must not bypass the check
		"ftp://example.com/bots.json",  // unsupported scheme
		"file://localhost/etc/passwd",  // file URLs with a host are rejected
		"file:relative/path.json",      // relative file paths are rejected
		"file:///etc/passwd#frag",      // accepted shape, sanity-checked below
	}

	for _, raw := range cases[:len(cases)-1] {
		_, err := NewRemoteAddressesURLChecker(t.Context(), raw, discardLogger())
		if !errors.Is(err, config.ErrInvalidRemoteAddressesURL) {
			t.Errorf("NewRemoteAddressesURLChecker(%q) err = %v, want %v", raw, err, config.ErrInvalidRemoteAddressesURL)
		}
		if err := parseRemoteAddressesURL(raw); !errors.Is(err, config.ErrInvalidRemoteAddressesURL) {
			t.Errorf("parseRemoteAddressesURL(%q) err = %v, want %v", raw, err, config.ErrInvalidRemoteAddressesURL)
		}
	}

	// Absolute local file URLs must remain usable.
	if err := parseRemoteAddressesURL(cases[len(cases)-1]); err != nil {
		t.Fatalf("parseRemoteAddressesURL(file URL) err = %v, want nil", err)
	}
	if err := parseRemoteAddressesURL("https://example.com/bots.json"); err != nil {
		t.Fatalf("parseRemoteAddressesURL(https URL) err = %v, want nil", err)
	}
}

func TestNewRemoteAddressesURLChecker_runStopsOnCancel(t *testing.T) {
	started := make(chan struct{})

	ctx, cancel := context.WithCancel(t.Context())
	c := newTestRemoteAddressesURLChecker("https://example.invalid/bots.json")
	c.client = &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: remoteAddressesRedirect,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			select {
			case <-started:
			default:
				close(started)
			}
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	}
	go c.run(ctx)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fetch did not start")
	}

	cancel()

	select {
	case <-c.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh goroutine did not stop after context cancel")
	}
}

func TestRemoteAddressesURLRejectsEmptyReplacement(t *testing.T) {
	c := newTestRemoteAddressesURLChecker("")
	for _, doc := range []string{samplePrefixList, `{}`, `{"prefixes":[]}`} {
		pl, err := iplist.Parse(strings.NewReader(doc))
		if err != nil {
			t.Fatal(err)
		}
		err = c.applyList(pl)
		if doc != samplePrefixList && err == nil {
			t.Errorf("accepted empty feed %s", doc)
		}
		if !checkIP(t, c, "20.42.10.176") {
			t.Fatal("loaded prefix lost")
		}
	}
}

func TestRemoteAddressesURLChecker_fileURL(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "prefixes-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, samplePrefixList); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	raw := (&url.URL{Scheme: "file", Path: f.Name()}).String()
	c := newTestRemoteAddressesURLChecker(raw)

	delay := c.refreshOnce(t.Context())
	if delay != c.refreshInterval {
		t.Fatalf("delay = %v, want %v", delay, c.refreshInterval)
	}
	if c.rebuildCount != 1 {
		t.Fatalf("rebuildCount = %d, want 1", c.rebuildCount)
	}
	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected file-sourced prefix to match")
	}
	if checkIP(t, c, "1.1.1.1") {
		t.Fatal("expected unrelated IP not to match")
	}
}

func TestRemoteAddressesURLChecker_fileURLMissing(t *testing.T) {
	t.Parallel()

	raw := (&url.URL{Scheme: "file", Path: filepath.Join(t.TempDir(), "missing.json")}).String()
	c := newTestRemoteAddressesURLChecker(raw)
	c.cycleStart = time.Now()

	if delay := c.refreshOnce(t.Context()); delay != c.retryInterval {
		t.Fatalf("delay = %v, want retry interval %v", delay, c.retryInterval)
	}
	if c.rebuildCount != 0 {
		t.Fatalf("rebuildCount = %d, want 0", c.rebuildCount)
	}
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("missing file must not populate the list")
	}
}

func TestRemoteAddressesURLChecker_fileURLDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	raw := (&url.URL{Scheme: "file", Path: dir}).String()
	c := newTestRemoteAddressesURLChecker(raw)
	c.cycleStart = time.Now()

	if delay := c.refreshOnce(t.Context()); delay != c.retryInterval {
		t.Fatalf("delay = %v, want retry interval %v", delay, c.retryInterval)
	}
	if c.rebuildCount != 0 {
		t.Fatalf("rebuildCount = %d, want 0", c.rebuildCount)
	}
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("directory feed must not populate the list")
	}
}

func TestNewRemoteAddressesURLChecker_rejectsFileURLWithHost(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"file://localhost/etc/bots.json",
		"file://server.example/share/bots.json",
	} {
		if _, err := NewRemoteAddressesURLChecker(t.Context(), raw, discardLogger()); !errors.Is(err, config.ErrInvalidRemoteAddressesURL) {
			t.Fatalf("NewRemoteAddressesURLChecker(%q) err = %v, want %v", raw, err, config.ErrInvalidRemoteAddressesURL)
		}
	}
}

func TestRemoteAddressesURLChecker_staleListExpires(t *testing.T) {
	t.Parallel()

	c := newTestRemoteAddressesURLChecker("https://example.com/bots.json")
	pl, err := iplist.Parse(strings.NewReader(samplePrefixList))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.applyList(pl); err != nil {
		t.Fatal(err)
	}
	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected loaded prefix to match before expiry")
	}

	// Within the staleness window the list stays authoritative even if
	// refreshes keep failing.
	c.mu.Lock()
	c.loadedAt = time.Now().Add(-remoteAddressesURLMaxStaleness + time.Minute)
	c.mu.Unlock()
	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("fresh list must keep matching inside the staleness window")
	}

	// Past the window, Check must fail closed and clear the stale CIDRs.
	c.mu.Lock()
	c.loadedAt = time.Now().Add(-remoteAddressesURLMaxStaleness - time.Minute)
	c.mu.Unlock()
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("stale list must no longer match after the staleness window")
	}

	c.mu.RLock()
	loadedAt := c.loadedAt
	prefixCount := c.prefixCount
	c.mu.RUnlock()
	if !loadedAt.IsZero() || prefixCount != 0 {
		t.Fatalf("stale list was not cleared: loadedAt=%v prefixCount=%d", loadedAt, prefixCount)
	}
}

func TestRemoteAddressesURLChecker_failureCycleClearsStaleList(t *testing.T) {
	t.Parallel()

	c := newTestRemoteAddressesURLChecker("https://example.com/bots.json")
	pl, err := iplist.Parse(strings.NewReader(samplePrefixList))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.applyList(pl); err != nil {
		t.Fatal(err)
	}

	c.mu.Lock()
	c.loadedAt = time.Now().Add(-remoteAddressesURLMaxStaleness - time.Minute)
	c.mu.Unlock()
	c.cycleStart = time.Now()

	// delayUntilNextCycle is reached once retries are exhausted or a
	// non-retryable failure occurs; it must evict the aged-out list.
	_ = c.delayUntilNextCycle()

	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("stale list must be cleared after failed refresh cycle")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.loadedAt.IsZero() {
		t.Fatalf("loadedAt = %v, want zero", c.loadedAt)
	}
}

func TestRemoteAddressesURLChecker_successfulRefreshResetsStaleness(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "prefixes-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, samplePrefixList); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	raw := (&url.URL{Scheme: "file", Path: f.Name()}).String()
	c := newTestRemoteAddressesURLChecker(raw)

	if err := func() error {
		pl, perr := iplist.Parse(strings.NewReader(samplePrefixList))
		if perr != nil {
			return perr
		}
		return c.applyList(pl)
	}(); err != nil {
		t.Fatal(err)
	}

	// Age the current list past the staleness window, then recover.
	c.mu.Lock()
	c.loadedAt = time.Now().Add(-remoteAddressesURLMaxStaleness - time.Hour)
	c.mu.Unlock()
	if checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected stale list to be cleared before recovery")
	}

	if delay := c.refreshOnce(t.Context()); delay != c.refreshInterval {
		t.Fatalf("recovery delay = %v, want %v", delay, c.refreshInterval)
	}
	c.mu.RLock()
	loadedAt := c.loadedAt
	c.mu.RUnlock()
	if loadedAt.IsZero() || time.Since(loadedAt) > time.Minute {
		t.Fatalf("loadedAt = %v, want a recent timestamp after recovery", loadedAt)
	}
	if !checkIP(t, c, "20.42.10.176") {
		t.Fatal("expected refreshed list to match again after recovery")
	}
}

func TestRemoteAddressesRedirectPolicy(t *testing.T) {
	t.Parallel()

	mustParse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	originReq := func(raw string) *http.Request {
		t.Helper()
		return &http.Request{URL: mustParse(raw)}
	}

	cases := []struct {
		name    string
		req     *http.Request
		via     []*http.Request
		wantErr bool
	}{
		{
			name:    "same origin path redirect",
			req:     originReq("https://example.com/feed"),
			via:     []*http.Request{{URL: mustParse("https://example.com/bots.json")}},
			wantErr: false,
		},
		{
			name:    "cross host redirect",
			req:     originReq("https://evil.example/feed"),
			via:     []*http.Request{{URL: mustParse("https://example.com/bots.json")}},
			wantErr: true,
		},
		{
			name:    "https to http downgrade",
			req:     originReq("http://example.com/feed"),
			via:     []*http.Request{{URL: mustParse("https://example.com/bots.json")}},
			wantErr: true,
		},
		{
			name:    "http to https upgrade on different host",
			req:     originReq("https://evil.example/feed"),
			via:     []*http.Request{{URL: mustParse("http://example.com/bots.json")}},
			wantErr: true,
		},
		{
			name:    "redirect to file scheme",
			req:     originReq("file:///etc/passwd"),
			via:     []*http.Request{{URL: mustParse("https://example.com/bots.json")}},
			wantErr: true,
		},
		{
			name:    "no history",
			req:     originReq("https://example.com/feed"),
			via:     nil,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := remoteAddressesRedirect(tc.req, tc.via)
			if tc.wantErr && !errors.Is(err, config.ErrInvalidRemoteAddressesURL) {
				t.Fatalf("err = %v, want %v", err, config.ErrInvalidRemoteAddressesURL)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

func TestRemoteAddressesURLRedirectOrigin(t *testing.T) {
	var reached atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		if _, err := io.WriteString(w, samplePrefixList); err != nil {
			t.Error(err)
		}
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/external":
			http.Redirect(w, r, other.URL, http.StatusFound)
		case "/local":
			http.Redirect(w, r, "/feed", http.StatusFound)
		default:
			if _, err := io.WriteString(w, samplePrefixList); err != nil {
				t.Error(err)
			}
		}
	}))
	defer origin.Close()
	for _, p := range []string{"/external", "/local"} {
		// Build the checker directly: httptest only serves plaintext HTTP,
		// which the constructor now rejects as an untrusted source. The
		// redirect policy under test is independent of that scheme gate.
		c := newTestRemoteAddressesURLChecker(origin.URL + p)
		c.client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: remoteAddressesRedirect}
		c.refreshOnce(t.Context())
		if p == "/external" && reached.Load() {
			t.Fatal("followed external redirect")
		}
		if p == "/local" && !checkIP(t, c, "20.42.10.176") {
			t.Fatal("same origin redirect failed")
		}
	}
}

// scriptedRoundTripper replies without binding any sockets, which keeps the
// redirect behavior testable in environments where listening is unavailable.
type scriptedRoundTripper struct {
	locations map[string]string
	visited   []string
}

func (s *scriptedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.visited = append(s.visited, req.URL.String())
	if loc, ok := s.locations[req.URL.Path]; ok {
		resp := &http.Response{
			Status:     "302 Found",
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
			Request:    req,
			Body:       io.NopCloser(strings.NewReader("")),
		}
		resp.Header.Set("Location", loc)
		return resp, nil
	}

	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    req,
		Body:       io.NopCloser(strings.NewReader(samplePrefixList)),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}

func TestRemoteAddressesURLChecker_redirectPolicyOverHTTP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		rawURL    string
		locations map[string]string
		wantMatch bool
	}{
		{
			name:   "same origin redirect succeeds",
			rawURL: "https://example.com/bots.json",
			locations: map[string]string{
				"/bots.json": "https://example.com/feed",
			},
			wantMatch: true,
		},
		{
			name:   "cross origin redirect rejected",
			rawURL: "https://example.com/bots.json",
			locations: map[string]string{
				"/bots.json": "https://evil.example/feed",
			},
			wantMatch: false,
		},
		{
			name:   "https to http downgrade rejected",
			rawURL: "https://example.com/bots.json",
			locations: map[string]string{
				"/bots.json": "http://example.com/feed",
			},
			wantMatch: false,
		},
		{
			name:   "redirect to file scheme rejected",
			rawURL: "https://example.com/bots.json",
			locations: map[string]string{
				"/bots.json": "file:///etc/passwd",
			},
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rt := &scriptedRoundTripper{locations: tc.locations}
			c := newTestRemoteAddressesURLChecker(tc.rawURL)
			c.client = &http.Client{CheckRedirect: remoteAddressesRedirect, Transport: rt}

			_ = c.refreshOnce(t.Context())

			if got := checkIP(t, c, "20.42.10.176"); got != tc.wantMatch {
				t.Fatalf("match = %v, want %v (visited %v)", got, tc.wantMatch, rt.visited)
			}

			// A blocked redirect must never leave the configured origin.
			if !tc.wantMatch {
				for _, visited := range rt.visited {
					u, err := url.Parse(visited)
					if err != nil {
						t.Fatal(err)
					}
					if u.Host != "example.com" || u.Scheme != "https" {
						t.Fatalf("request left the configured origin: %q", visited)
					}
				}
			}
		})
	}
}

func TestRemoteAddressesURLChecker_4xxIsNonRetryable(t *testing.T) {
	t.Parallel()

	c := newTestRemoteAddressesURLChecker("https://example.com/bots.json")
	c.client = &http.Client{
		CheckRedirect: remoteAddressesRedirect,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "404 Not Found",
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Request:    req,
				Body:       io.NopCloser(strings.NewReader("nope")),
			}, nil
		}),
	}
	c.cycleStart = time.Now()

	delay := c.refreshOnce(t.Context())
	if delay < 23*time.Hour || delay > 24*time.Hour {
		t.Fatalf("delay = %v, want remainder of 24h window", delay)
	}
	if c.consecutiveFail != 0 {
		t.Fatalf("consecutiveFail = %d, want 0 (4xx is not retried)", c.consecutiveFail)
	}
	if c.rebuildCount != 0 {
		t.Fatalf("rebuildCount = %d, want 0", c.rebuildCount)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
