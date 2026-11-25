package lib

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
)

func TestChallengeTicketBindsIssuingClientUID39196(t *testing.T) {
	srv := spawnAnubis(t, Options{Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream"))
	}), Policy: loadPolicies(t, "testdata/zero_difficulty.yaml", 0)})
	srv.opts.CookieExpiration = time.Hour

	issueReq := httptest.NewRequest(http.MethodGet, "/", nil)
	issueReq.Header.Set("User-Agent", "issuer-agent")
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

	newPass := func(ua, ip string) *httptest.ResponseRecorder {
		q := "redir=%2F&id=" + issued.ID + "&nonce=0&elapsedTime=1&response=" + internal.SHA256sum(issued.RandomData+"0")
		req := httptest.NewRequest(http.MethodGet, "/?"+q, nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Real-IP", ip)
		req.AddCookie(&http.Cookie{Name: srv.cookieName(anubis.TestCookieName), Value: issued.ID})
		rec := httptest.NewRecorder()
		srv.PassChallenge(rec, req)
		return rec
	}

	for _, tc := range []struct {
		name string
		ua   string
		ip   string
	}{
		{"different UA", "attacker-agent", "192.0.2.10"},
		{"different IP", "issuer-agent", "198.51.100.20"},
		{"different UA and IP", "attacker-agent", "198.51.100.20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newPass(tc.ua, tc.ip)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			if ckie := authCookie(srv, rec.Result()); ckie != nil {
				t.Fatalf("cross-client request minted cookie %v", ckie)
			}
		})
	}

	rec := newPass("issuer-agent", "192.0.2.10")
	if rec.Code != http.StatusFound {
		t.Fatalf("same client status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	if ckie := authCookie(srv, rec.Result()); ckie == nil {
		t.Fatal("same client did not receive clearance cookie")
	}

	auth := authCookie(srv, rec.Result())
	sameProtected := httptest.NewRequest(http.MethodGet, "/protected", nil)
	sameProtected.Header.Set("User-Agent", "issuer-agent")
	sameProtected.Header.Set("X-Real-IP", "192.0.2.10")
	sameProtected.AddCookie(auth)
	sameRec := httptest.NewRecorder()
	srv.maybeReverseProxyOrPage(sameRec, sameProtected)
	if sameRec.Code != http.StatusOK || sameRec.Body.String() != "upstream" {
		t.Fatalf("same client could not enter upstream: code=%d body=%q", sameRec.Code, sameRec.Body.String())
	}
}
