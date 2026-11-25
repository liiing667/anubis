package lib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/store"
	"github.com/golang-jwt/jwt/v5"
)

func TestInsecureSameSiteNoneCannotMintClearanceUID39201(t *testing.T) {
	t.Run("construction rejects unsafe combination", func(t *testing.T) {
		srv, err := New(Options{
			Policy:         loadPolicies(t, "testdata/zero_difficulty.yaml", 0),
			CookieSecure:   false,
			CookieSameSite: http.SameSiteNoneMode,
		})
		if err == nil {
			t.Fatal("expected New to reject SameSite=None without Secure")
		}
		if srv != nil {
			t.Fatalf("New returned a server for unsafe cookie settings: %#v", srv)
		}
	})

	for _, tc := range []struct {
		name     string
		secure   bool
		sameSite http.SameSite
		wantMint bool
	}{
		{name: "none secure", secure: true, sameSite: http.SameSiteNoneMode, wantMint: true},
		{name: "lax insecure", secure: false, sameSite: http.SameSiteLaxMode, wantMint: true},
		{name: "strict insecure", secure: false, sameSite: http.SameSiteStrictMode, wantMint: true},
		{name: "none insecure", secure: false, sameSite: http.SameSiteNoneMode, wantMint: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			srv := spawnAnubis(t, Options{
				Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					_, _ = w.Write([]byte("upstream"))
				}),
				Policy:           loadPolicies(t, "testdata/zero_difficulty.yaml", 0),
				CookieExpiration: time.Hour,
				CookieSecure:     true,
				CookieSameSite:   http.SameSiteLaxMode,
			})
			// Exercise the request-time gate as well. New rejects this
			// combination directly; mutating the constructed options models a
			// server whose configuration changed after construction.
			srv.opts.CookieSecure = tc.secure
			srv.opts.CookieSameSite = tc.sameSite

			issueReq := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			issueReq.Header.Set("User-Agent", "Mozilla/5.0")
			issueReq.Header.Set("X-Real-IP", "192.0.2.10")
			lg, issueReq := srv.getRequestLogger(issueReq)
			cr, rule, err := srv.check(issueReq, lg)
			if err != nil {
				t.Fatal(err)
			}

			issued, err := srv.issueChallenge(issueReq.Context(), issueReq, lg, cr, rule)
			if err != nil {
				t.Fatal(err)
			}

			q := url.Values{}
			q.Set("redir", "/")
			q.Set("id", issued.ID)
			q.Set("nonce", "0")
			q.Set("elapsedTime", "1")
			q.Set("response", internal.SHA256sum(issued.RandomData+"0"))

			passReq := httptest.NewRequest(http.MethodGet, "http://example.test/pass?"+q.Encode(), nil)
			passReq.Header.Set("User-Agent", "Mozilla/5.0")
			passReq.Header.Set("X-Real-IP", "192.0.2.10")
			passReq.AddCookie(&http.Cookie{Name: srv.cookieName(anubis.TestCookieName), Value: issued.ID})

			passRec := httptest.NewRecorder()
			srv.PassChallenge(passRec, passReq)
			passResp := passRec.Result()
			clearance := authCookie(srv, passResp)

			if !tc.wantMint {
				if passRec.Code < http.StatusBadRequest {
					t.Fatalf("unsafe cookie combo returned success status %d", passRec.Code)
				}
				if clearance != nil {
					t.Fatalf("unsafe cookie combo minted clearance: %#v", clearance)
				}

				j := store.JSON[challenge.Challenge]{Underlying: srv.store}
				stored, err := j.Get(context.Background(), "challenge:"+issued.ID)
				if err != nil {
					t.Fatal(err)
				}
				if stored.Spent {
					t.Fatal("refused clearance marked the challenge record as spent")
				}

				token, err := srv.signJWT(jwt.MapClaims{
					"challenge":  issued.ID,
					"method":     rule.Challenge.Algorithm,
					"policyRule": rule.Hash(),
					"action":     string(cr.Rule),
				})
				if err != nil {
					t.Fatal(err)
				}

				replayReq := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
				replayReq.Header.Set("User-Agent", "Mozilla/5.0")
				replayReq.Header.Set("X-Real-IP", "192.0.2.10")
				replayReq.AddCookie(&http.Cookie{
					Name:  srv.cookieName(anubis.CookieName),
					Value: token,
				})
				replayRec := httptest.NewRecorder()
				srv.maybeReverseProxyOrPage(replayRec, replayReq)

				if upstreamCalls.Load() != 0 {
					t.Fatal("replayed clearance with unsafe cookie settings reached upstream")
				}
				return
			}

			if passRec.Code != http.StatusFound {
				t.Fatalf("wanted status %d, got %d: %s", http.StatusFound, passRec.Code, passRec.Body.String())
			}
			if clearance == nil {
				t.Fatal("supported cookie setting did not mint clearance")
			}
			if clearance.Secure != tc.secure {
				t.Fatalf("secure flag = %v, want %v", clearance.Secure, tc.secure)
			}
			if clearance.SameSite != tc.sameSite {
				t.Fatalf("SameSite = %v, want %v", clearance.SameSite, tc.sameSite)
			}

			authReq := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			authReq.Header.Set("User-Agent", "Mozilla/5.0")
			authReq.Header.Set("X-Real-IP", "192.0.2.10")
			authReq.AddCookie(clearance)
			authRec := httptest.NewRecorder()
			srv.maybeReverseProxyOrPage(authRec, authReq)

			if authRec.Code != http.StatusOK || upstreamCalls.Load() != 1 {
				t.Fatalf("valid clearance did not reach upstream: status=%d calls=%d body=%q", authRec.Code, upstreamCalls.Load(), authRec.Body.String())
			}
		})
	}
}
