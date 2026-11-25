package lib

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TecharoHQ/anubis"
	"github.com/TecharoHQ/anubis/internal"
	"github.com/TecharoHQ/anubis/lib/challenge"
	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/TecharoHQ/anubis/lib/policy"
	"github.com/TecharoHQ/anubis/lib/store"
)

type agentZeroCostStore struct {
	store.Interface
	challengeSets int
}

func (s *agentZeroCostStore) Set(ctx context.Context, key string, value []byte, expiry time.Duration) error {
	if strings.HasPrefix(key, "challenge:") {
		s.challengeSets++
	}
	return s.Interface.Set(ctx, key, value, expiry)
}

func TestAgentZeroCostChallengeNotIssued(t *testing.T) {
	srv := spawnAnubis(t, Options{Next: http.NewServeMux(), Policy: loadPolicies(t, "testdata/zero_difficulty.yaml", 0)})
	st := &agentZeroCostStore{Interface: srv.store}
	srv.store = st

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "192.0.2.10")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	lg, req := srv.getRequestLogger(req)

	cr, rule, err := srv.check(req, lg)
	if err != nil {
		t.Fatal(err)
	}

	chall, err := srv.issueChallenge(req.Context(), req, lg, cr, rule)
	if !errors.Is(err, ErrZeroCostChallenge) {
		t.Fatalf("expected ErrZeroCostChallenge, got chall=%v err=%v", chall, err)
	}
	if chall != nil {
		t.Fatalf("issuance returned a challenge on zero cost: %#v", chall)
	}
	if st.challengeSets != 0 {
		t.Fatalf("zero-cost challenge was persisted %d times", st.challengeSets)
	}

	apiReq := httptest.NewRequest(http.MethodPost, "/.within.website/x/cmd/anubis/api/make-challenge?redir=%2F", nil)
	apiReq.Header.Set("X-Real-IP", "192.0.2.10")
	apiReq.Header.Set("User-Agent", "Mozilla/5.0")
	apiRec := httptest.NewRecorder()
	srv.MakeChallenge(apiRec, apiReq)
	if apiRec.Code < http.StatusBadRequest {
		t.Fatalf("zero-cost MakeChallenge returned success status %d", apiRec.Code)
	}
	if st.challengeSets != 0 {
		t.Fatalf("zero-cost MakeChallenge persisted %d challenges", st.challengeSets)
	}
}

func TestAgentZeroCostChallengeNotConsumed(t *testing.T) {
	srv := spawnAnubis(t, Options{Next: http.NewServeMux(), Policy: loadPolicies(t, "testdata/zero_difficulty.yaml", 0)})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "192.0.2.11")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	lg, req := srv.getRequestLogger(req)
	cr, rule, err := srv.check(req, lg)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Rule != config.RuleChallenge || rule.Challenge == nil {
		t.Fatalf("test policy did not produce a challenge rule: %#v", cr)
	}

	chall := challenge.Challenge{
		ID:             "zero-cost-manual",
		Method:         rule.Challenge.Algorithm,
		RandomData:     "zero-cost-random-data",
		IssuedAt:       time.Now(),
		Difficulty:     0,
		PolicyRuleHash: rule.Hash(),
		Extensions:     rule.Challenge.Extensions,
	}
	j := store.JSON[challenge.Challenge]{Underlying: srv.store}
	if err := j.Set(req.Context(), "challenge:"+chall.ID, chall, time.Minute); err != nil {
		t.Fatal(err)
	}

	pass := httptest.NewRequest(http.MethodGet, "/?redir=%2F&id="+chall.ID+
		"&nonce=0&elapsedTime=1&response="+internal.SHA256sum(chall.RandomData+"0"), nil)
	pass.Header.Set("X-Real-IP", "192.0.2.11")
	pass.Header.Set("User-Agent", "Mozilla/5.0")
	pass.AddCookie(&http.Cookie{Name: srv.cookieName(anubis.TestCookieName), Value: chall.ID})

	rec := httptest.NewRecorder()
	srv.PassChallenge(rec, pass)
	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
	if ckie := authCookie(srv, resp); ckie != nil {
		t.Fatalf("zero-cost challenge minted clearance cookie: %#v", ckie)
	}

	stored, err := j.Get(req.Context(), "challenge:"+chall.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Spent {
		t.Fatal("rejected zero-cost challenge was marked spent")
	}
}

func TestAgentPositiveDifficultyStillPasses(t *testing.T) {
	pol := loadPolicies(t, "testdata/zero_difficulty.yaml", 1)
	pol.DefaultDifficulty = 1
	pol.Thresholds[0].Challenge.Difficulty = 1
	srv := spawnAnubis(t, Options{Next: http.NewServeMux(), Policy: pol})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "192.0.2.12")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	lg, req := srv.getRequestLogger(req)
	cr, rule, err := srv.check(req, lg)
	if err != nil {
		t.Fatal(err)
	}

	chall, err := srv.issueChallenge(req.Context(), req, lg, cr, rule)
	if err != nil {
		t.Fatal(err)
	}

	nonce := 0
	response := ""
	for {
		response = internal.SHA256sum(chall.RandomData + strconv.Itoa(nonce))
		if strings.HasPrefix(response, "0") {
			break
		}
		nonce++
	}

	pass := httptest.NewRequest(http.MethodGet, "/?redir=%2F&id="+chall.ID+
		"&nonce="+strconv.Itoa(nonce)+"&elapsedTime=1&response="+response, nil)
	pass.Header.Set("X-Real-IP", "192.0.2.12")
	pass.Header.Set("User-Agent", "Mozilla/5.0")
	pass.AddCookie(&http.Cookie{Name: srv.cookieName(anubis.TestCookieName), Value: chall.ID})

	rec := httptest.NewRecorder()
	srv.PassChallenge(rec, pass)
	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if ckie := authCookie(srv, resp); ckie == nil {
		t.Fatal("positive-difficulty challenge did not mint clearance cookie")
	}
}

func TestAgentExplicitBenchmarkModePreserved(t *testing.T) {
	srv := spawnAnubis(t, Options{Next: http.NewServeMux(), Policy: loadPolicies(t, "testdata/zero_difficulty.yaml", 0)})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "192.0.2.13")
	lg, _ := srv.getRequestLogger(req)
	rec := httptest.NewRecorder()

	if handled := srv.checkRules(rec, req, cr("benchmark", config.RuleBenchmark, 0), lg, &policy.Bot{}); !handled {
		t.Fatal("benchmark rule was not handled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected benchmark page status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestAgentStatusOnlyMonitoringPreserved(t *testing.T) {
	srv := spawnAnubis(t, Options{Next: http.NewServeMux(), Policy: loadPolicies(t, "testdata/zero_difficulty.yaml", 0)})
	st := &agentZeroCostStore{Interface: srv.store}
	srv.store = st

	req := httptest.NewRequest(http.MethodGet, "/.within.website/x/cmd/anubis/api/check", nil)
	req.Header.Set("X-Real-IP", "192.0.2.14")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	srv.maybeReverseProxyHttpStatusOnly(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected monitor/status endpoint %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	if st.challengeSets != 0 {
		t.Fatalf("status-only monitor created a redeemable challenge: %d writes", st.challengeSets)
	}
}
