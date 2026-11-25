package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/internal/iplist"
	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/TecharoHQ/anubis/lib/policy/checker"
	"github.com/gaissmai/bart"
)

const (
	remoteAddressesURLRefreshInterval = 24 * time.Hour
	remoteAddressesURLRetryInterval   = 15 * time.Minute
	remoteAddressesURLMaxRetries      = 5
	remoteAddressesURLHTTPTimeout     = 30 * time.Second
	remoteAddressesURLMaxBodyBytes    = 8 << 20
	// remoteAddressesURLMaxStaleness bounds how long a previously loaded
	// prefix list stays authoritative after refreshes start failing. Once the
	// limit is reached the stale list is discarded so an attacker cannot rely
	// on revoked CIDRs remaining trusted forever (fail closed).
	remoteAddressesURLMaxStaleness = 2 * remoteAddressesURLRefreshInterval
)

// RemoteAddressesURLChecker matches client IPs against a prefix list fetched
// from a remote JSON document. The list starts empty and is replaced on each
// successful refresh. Failed fetches keep a previously loaded list until
// remoteAddressesURLMaxStaleness elapses, after which the stale list is
// cleared. Only https:// and local file:// sources are accepted so that an
// on-path attacker can never substitute a trusted list for an untrusted one.
type RemoteAddressesURLChecker struct {
	url       string
	parsedURL *url.URL
	logger    *slog.Logger
	client    *http.Client

	mu           sync.RWMutex
	prefixTable  *bart.Lite
	hash         string
	creationTime string
	rebuildCount int
	prefixCount  int
	loadedAt     time.Time

	cycleStart      time.Time
	consecutiveFail int

	refreshInterval time.Duration
	retryInterval   time.Duration
	maxRetries      int

	stopped chan struct{}
}

func NewRemoteAddressesURLChecker(ctx context.Context, rawURL string, logger *slog.Logger) (checker.Impl, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := parseRemoteAddressesURL(rawURL); err != nil {
		return nil, err
	}
	parsedURL, _ := url.Parse(strings.TrimSpace(rawURL))

	c := &RemoteAddressesURLChecker{
		url:             rawURL,
		parsedURL:       parsedURL,
		logger:          logger,
		client:          &http.Client{Timeout: remoteAddressesURLHTTPTimeout, CheckRedirect: remoteAddressesRedirect},
		prefixTable:     new(bart.Lite),
		hash:            internal.FastHash(""),
		refreshInterval: remoteAddressesURLRefreshInterval,
		retryInterval:   remoteAddressesURLRetryInterval,
		maxRetries:      remoteAddressesURLMaxRetries,
		stopped:         make(chan struct{}),
	}

	go c.run(ctx)
	return c, nil
}

// isSecureRemoteAddressesURL reports whether rawURL is an acceptable source
// for a trusted prefix list. Only HTTPS endpoints and local file:// URLs are
// allowed; plaintext HTTP (or any other scheme) must be rejected because an
// on-path attacker could otherwise replace the administrator's trusted CIDR
// set with an attacker-controlled one.
func isSecureRemoteAddressesURL(rawURL string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, false
	}

	switch u.Scheme {
	case "https":
		return u, u.Host != ""
	case "file":
		// A file URL is only trustworthy when it points at an absolute local
		// path with no host component. file://host/path is rejected.
		return u, u.Host == "" && u.Path != "" && filepath.IsAbs(u.Path)
	default:
		return nil, false
	}
}

func parseRemoteAddressesURL(rawURL string) error {
	if _, ok := isSecureRemoteAddressesURL(rawURL); !ok {
		return fmt.Errorf("%w: %q", config.ErrInvalidRemoteAddressesURL, rawURL)
	}
	return nil
}

func (c *RemoteAddressesURLChecker) Check(r *http.Request) (bool, error) {
	host := r.Header.Get("X-Real-IP")
	if host == "" {
		return false, fmt.Errorf("%w: header X-Real-IP is not set", ErrMisconfiguration)
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false, fmt.Errorf("%w: %s is not an IP address: %w", ErrMisconfiguration, host, err)
	}

	if addr.Is6() && addr.Is4In6() {
		addr = addr.Unmap()
	}

	c.mu.RLock()
	table := c.prefixTable
	loadedAt := c.loadedAt
	c.mu.RUnlock()

	// Fail closed: a list that could not be refreshed within the staleness
	// window must no longer authorize traffic.
	if !loadedAt.IsZero() && time.Since(loadedAt) > remoteAddressesURLMaxStaleness {
		c.clearList("prefix list exceeded max staleness during Check")
		c.mu.RLock()
		table = c.prefixTable
		c.mu.RUnlock()
	}

	if table == nil {
		return false, nil
	}

	return table.Contains(addr), nil
}

func (c *RemoteAddressesURLChecker) Hash() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hash
}

func (c *RemoteAddressesURLChecker) run(ctx context.Context) {
	defer close(c.stopped)

	for {
		if ctx.Err() != nil {
			return
		}

		delay := c.refreshOnce(ctx)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}

func (c *RemoteAddressesURLChecker) refreshOnce(ctx context.Context) time.Duration {
	if c.cycleStart.IsZero() {
		c.cycleStart = time.Now()
	}

	body, err := c.fetch(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		return c.handleRetryable(ctx, "can't fetch remote_addresses_url", err)
	}
	if closer, ok := body.(io.Closer); ok {
		defer closer.Close() //nolint:errcheck
	}
	pl, err := iplist.Parse(body)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to parse remote_addresses_url", "url", c.url, "err", err)
		return c.delayUntilNextCycle()
	}

	if err := c.applyList(pl); err != nil {
		c.logger.WarnContext(ctx, "failed to apply remote_addresses_url", "url", c.url, "err", err)
		return c.delayUntilNextCycle()
	}

	c.cycleStart = time.Now()
	c.consecutiveFail = 0
	return c.refreshInterval
}

// fetch retrieves the raw prefix list document. HTTPS requests go through the
// hardened HTTP client (same-origin, no scheme downgrade), while file:// URLs
// are read directly from the local filesystem.
func (c *RemoteAddressesURLChecker) fetch(ctx context.Context) (io.Reader, error) {
	if c.parsedURL.Scheme == "file" {
		return c.fetchFile()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build remote_addresses_url request: %w", err)
	}
	req.Header.Set("User-Agent", "TecharoHQ-Anubis/"+anubis.Version)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	switch {
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("remote_addresses_url fetch returned server error: http status %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		return nil, &nonRetryableFetchError{fmt.Errorf("remote_addresses_url fetch returned client error: http status %d", resp.StatusCode)}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("remote_addresses_url fetch returned unexpected status: http status %d", resp.StatusCode)
	}

	return io.LimitReader(resp.Body, remoteAddressesURLMaxBodyBytes), nil
}

// nonRetryableFetchError marks a fetch failure (for example an HTTP 4xx) that
// should not be retried and simply waits for the next refresh window.
type nonRetryableFetchError struct {
	err error
}

func (e *nonRetryableFetchError) Error() string { return e.err.Error() }
func (e *nonRetryableFetchError) Unwrap() error { return e.err }

func (c *RemoteAddressesURLChecker) fetchFile() (io.Reader, error) {
	// URL paths are slash-separated even on Windows; FromSlash normalizes the
	// separators and Clean removes any redundant components.
	path := filepath.Clean(filepath.FromSlash(c.parsedURL.Path))
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("remote_addresses_url file path %q is not absolute", c.parsedURL.Path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("can't open remote_addresses_url file %q: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("can't stat remote_addresses_url file %q: %w", path, err)
	}
	if info.IsDir() {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("remote_addresses_url file %q is a directory", path)
	}

	return &limitedReadCloser{
		Reader: io.LimitReader(f, remoteAddressesURLMaxBodyBytes),
		Closer: f,
	}, nil
}

// limitedReadCloser keeps the body size bounded while ensuring the underlying
// file handle is released.
type limitedReadCloser struct {
	io.Reader
	io.Closer
}

func (c *RemoteAddressesURLChecker) applyList(pl *iplist.PrefixList) error {
	if pl.CreationTime != "" && pl.CreationTime == c.creationTime {
		c.logger.Debug("remote_addresses_url unchanged, skip rebuild", "url", c.url, "creationTime", pl.CreationTime)
		return nil
	}

	cidrs := pl.CIDRs()
	if len(cidrs) == 0 {
		return config.ErrInvalidRemoteAddressesURL
	}
	table := new(bart.Lite)
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		table.Insert(prefix)
	}

	hash := internal.FastHash(strings.Join(cidrs, ","))

	c.mu.Lock()
	c.prefixTable = table
	c.hash = hash
	c.creationTime = pl.CreationTime
	c.rebuildCount++
	c.prefixCount = len(cidrs)
	c.loadedAt = time.Now()
	c.mu.Unlock()

	c.logger.Info("updated remote_addresses_url", "url", c.url, "prefixes", len(cidrs), "creationTime", pl.CreationTime)
	return nil
}

// clearList discards the currently trusted prefix set. It is used when the
// loaded data has aged past remoteAddressesURLMaxStaleness so revoked CIDRs
// cannot remain effective indefinitely.
func (c *RemoteAddressesURLChecker) clearList(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.loadedAt.IsZero() {
		return
	}

	if c.prefixTable != nil {
		c.logger.Warn("clearing stale remote_addresses_url prefix list", "url", c.url, "reason", reason, "prefixes", c.prefixCount)
	}
	c.prefixTable = new(bart.Lite)
	c.hash = internal.FastHash("")
	c.creationTime = ""
	c.prefixCount = 0
	c.loadedAt = time.Time{}
}

// isLoadedListStale reports whether the currently loaded prefix list has
// exceeded the maximum staleness window.
func (c *RemoteAddressesURLChecker) isLoadedListStale(now time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.loadedAt.IsZero() && now.Sub(c.loadedAt) > remoteAddressesURLMaxStaleness
}

func (c *RemoteAddressesURLChecker) handleRetryable(ctx context.Context, msg string, err error) time.Duration {
	var nonRetryable *nonRetryableFetchError
	if errors.As(err, &nonRetryable) {
		c.logger.WarnContext(ctx, msg, "url", c.url, "err", err)
		return c.delayUntilNextCycle()
	}

	c.consecutiveFail++
	if c.consecutiveFail < c.maxRetries {
		c.logger.WarnContext(ctx, msg, "url", c.url, "attempt", c.consecutiveFail, "err", err)
		return c.retryInterval
	}

	c.logger.WarnContext(ctx, "remote_addresses_url fetch failed, giving up until next refresh window", "url", c.url, "attempts", c.consecutiveFail, "err", err)
	return c.delayUntilNextCycle()
}

func (c *RemoteAddressesURLChecker) delayUntilNextCycle() time.Duration {
	c.consecutiveFail = 0
	if c.isLoadedListStale(time.Now()) {
		c.clearList("refresh failures exceeded staleness window")
	}
	remaining := time.Until(c.cycleStart.Add(c.refreshInterval))
	if remaining < 0 {
		remaining = 0
	}
	c.cycleStart = time.Time{}
	return remaining
}

// remoteAddressesRedirect only permits redirects that stay on the exact
// origin (scheme + host) of the configured URL. This blocks cross-origin
// pivots into internal services as well as downgrades from https:// to
// plaintext http:// where an on-path attacker could substitute the list.
func remoteAddressesRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) >= 10 {
		return config.ErrInvalidRemoteAddressesURL
	}
	origin := via[0].URL
	if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
		return config.ErrInvalidRemoteAddressesURL
	}
	return nil
}
