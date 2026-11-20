package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/home"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func claudeExtraUsageSignals(now time.Time, overrides map[string]string) map[string]string {
	reset := strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10)
	signals := map[string]string{
		"Anthropic-Ratelimit-Unified-Status":               "rejected",
		"Anthropic-Ratelimit-Unified-Reset":                reset,
		"Anthropic-Ratelimit-Unified-Representative-Claim": "five_hour",
		"Anthropic-Ratelimit-Unified-5h-Status":            "rejected",
		"Anthropic-Ratelimit-Unified-5h-Reset":             reset,
		"Anthropic-Ratelimit-Unified-Overage-Status":       "allowed",
		"Anthropic-Ratelimit-Unified-Overage-Reset":        strconv.FormatInt(now.Add(20*24*time.Hour).Unix(), 10),
	}
	for key, value := range overrides {
		if value == "" {
			delete(signals, key)
			continue
		}
		signals[key] = value
	}
	return signals
}

func TestClaudeExtraUsageResetAt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	tests := []struct {
		name            string
		overrides       map[string]string
		credentialLevel bool
		want            time.Duration
		blocked         bool
	}{
		{name: "plan limit used up with overage allowed", credentialLevel: true, want: 2 * time.Hour, blocked: true},
		{name: "overage allowed_warning", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Overage-Status": "allowed_warning"}, credentialLevel: true, want: 2 * time.Hour, blocked: true},
		{name: "overage rejected is a real upstream 429", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Overage-Status": "rejected"}, credentialLevel: true},
		{name: "overage status missing", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Overage-Status": ""}, credentialLevel: true},
		{name: "plan limit not used up", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed_warning", "Anthropic-Ratelimit-Unified-5h-Status": "allowed_warning"}, credentialLevel: true},
		{name: "reset already passed", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Reset": at(-time.Minute), "Anthropic-Ratelimit-Unified-5h-Reset": at(-time.Minute)}, credentialLevel: true},
		{name: "no reset", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Reset": "", "Anthropic-Ratelimit-Unified-5h-Reset": ""}, credentialLevel: true},
		{name: "reset beyond any plan window", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Reset": at(9 * 24 * time.Hour), "Anthropic-Ratelimit-Unified-5h-Reset": ""}, credentialLevel: true},
		{name: "latest rejected window reset wins", overrides: map[string]string{"Anthropic-Ratelimit-Unified-7d-Status": "rejected", "Anthropic-Ratelimit-Unified-7d-Reset": at(30 * time.Hour)}, credentialLevel: true, want: 30 * time.Hour, blocked: true},
		{name: "allowed window reset is ignored", overrides: map[string]string{"Anthropic-Ratelimit-Unified-7d-Status": "allowed", "Anthropic-Ratelimit-Unified-7d-Reset": at(30 * time.Hour)}, credentialLevel: true, want: 2 * time.Hour, blocked: true},
		{
			name:            "per-model weekly claim does not block the whole credential",
			overrides:       map[string]string{"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus", "Anthropic-Ratelimit-Unified-5h-Status": "allowed"},
			credentialLevel: true,
		},
		{
			name: "shared deadline ignores a per-model weekly reset",
			overrides: map[string]string{
				"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
				"Anthropic-Ratelimit-Unified-Reset":                at(6 * 24 * time.Hour),
				"Anthropic-Ratelimit-Unified-5h-Reset":             at(time.Hour),
				"Anthropic-Ratelimit-Unified-7d_opus-Status":       "rejected",
				"Anthropic-Ratelimit-Unified-7d_opus-Reset":        at(6 * 24 * time.Hour),
			},
			credentialLevel: true,
			want:            time.Hour,
			blocked:         true,
		},
		{
			name: "model deadline keeps the per-model weekly reset",
			overrides: map[string]string{
				"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
				"Anthropic-Ratelimit-Unified-Reset":                at(6 * 24 * time.Hour),
				"Anthropic-Ratelimit-Unified-5h-Reset":             at(time.Hour),
				"Anthropic-Ratelimit-Unified-7d_opus-Status":       "rejected",
				"Anthropic-Ratelimit-Unified-7d_opus-Reset":        at(6 * 24 * time.Hour),
			},
			want:    6 * 24 * time.Hour,
			blocked: true,
		},
		{
			name: "stale shared rejection does not extend a per-model block to the credential",
			overrides: map[string]string{
				"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
				"Anthropic-Ratelimit-Unified-Reset":                at(6 * 24 * time.Hour),
				"Anthropic-Ratelimit-Unified-5h-Reset":             at(-time.Minute),
			},
			credentialLevel: true,
		},
		{
			name:      "per-model weekly claim blocks that model",
			overrides: map[string]string{"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus", "Anthropic-Ratelimit-Unified-5h-Status": "allowed"},
			want:      2 * time.Hour,
			blocked:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetAt, blocked := claudeExtraUsageResetAt(claudeExtraUsageSignals(now, tt.overrides), tt.credentialLevel, now)
			if blocked != tt.blocked {
				t.Fatalf("blocked = %v, want %v", blocked, tt.blocked)
			}
			if blocked && resetAt.Sub(now) != tt.want {
				t.Fatalf("reset in %v, want %v", resetAt.Sub(now), tt.want)
			}
		})
	}
}

func TestClaudeExtraUsagePolicyPrecedence(t *testing.T) {
	tests := []struct {
		global, credential string
		want               bool
	}{
		{global: "", credential: "", want: false},
		{global: "allow", credential: "", want: false},
		{global: "block", credential: "", want: true},
		{global: "block", credential: "allow", want: false},
		{global: "allow", credential: "block", want: true},
		{global: "", credential: "BLOCK", want: true},
		{global: "block", credential: "sometimes", want: true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("global=%q/credential=%q", tt.global, tt.credential), func(t *testing.T) {
			cfg := &internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: tt.global}}
			auth := &Auth{Provider: "claude", Attributes: map[string]string{AttributeClaudeExtraUsage: tt.credential}}
			if got := claudeExtraUsageBlocked(cfg, auth); got != tt.want {
				t.Fatalf("claudeExtraUsageBlocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyClaudeExtraUsageMetadata(t *testing.T) {
	auth := &Auth{Metadata: map[string]any{"extra_usage": " Block "}}
	ApplyClaudeExtraUsageMetadata(auth)
	if got := auth.Attributes[AttributeClaudeExtraUsage]; got != "block" {
		t.Fatalf("attribute = %q, want block", got)
	}
	auth.Metadata["extra_usage"] = "maybe"
	ApplyClaudeExtraUsageMetadata(auth)
	if _, ok := auth.Attributes[AttributeClaudeExtraUsage]; ok {
		t.Fatalf("invalid value kept attribute %q", auth.Attributes[AttributeClaudeExtraUsage])
	}
}

func newClaudeExtraUsageTestManager(t *testing.T, model, policy string, signalsByAuth map[string]map[string]string) (*Manager, *afterAuthTestExecutor, *recordingResultHook) {
	t.Helper()
	executor := &afterAuthTestExecutor{id: "claude"}
	hook := &recordingResultHook{}
	manager := NewManager(nil, &FillFirstSelector{}, hook)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: policy}})
	manager.SetRetryConfig(2, 0, 5)
	manager.RegisterExecutor(executor)
	for _, id := range []string{"cred-a", "cred-b"} {
		registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		auth := &Auth{ID: id, Provider: "claude", Status: StatusActive, Quota: QuotaState{Signals: signalsByAuth[id]}}
		if _, errReg := manager.Register(context.Background(), auth); errReg != nil {
			t.Fatal(errReg)
		}
	}
	return manager, executor, hook
}

func TestClaudeExtraUsageBlockSkipsCredentialWithoutCoolingIt(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-skip-" + mode
			now := time.Now()
			manager, executor, hook := newClaudeExtraUsageTestManager(t, model, "block", map[string]map[string]string{
				"cred-a": claudeExtraUsageSignals(now, nil),
			})

			payload, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, cliproxyexecutor.Options{})
			if errInvoke != nil {
				t.Fatalf("invoke error = %v", errInvoke)
			}
			if string(payload) != "ok:cred-b" {
				t.Fatalf("payload = %q, want ok:cred-b", payload)
			}
			if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-b"}) {
				t.Fatalf("executor calls = %v, want [cred-b]", calls)
			}
			for _, res := range hook.Results() {
				if res.AuthID == "cred-a" {
					t.Fatalf("refused credential was reported: %+v", res)
				}
			}
			credA, _ := manager.GetByID("cred-a")
			if credA == nil || credA.Unavailable || credA.Quota.Exceeded || !credA.NextRetryAfter.IsZero() {
				t.Fatalf("refused credential state changed: %+v", credA)
			}

			// Switching the policy back to allow takes effect on the next request.
			manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "allow"}})
			payload, errInvoke = invokeAfterAuthMode(manager, "claude", model, mode, cliproxyexecutor.Options{})
			if errInvoke != nil || string(payload) != "ok:cred-a" {
				t.Fatalf("after allow: payload = %q, error = %v, want ok:cred-a", payload, errInvoke)
			}
		})
	}
}

func TestClaudeExtraUsageBlockAllCredentialsReturnsPlanLimit429(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-all-" + mode
			now := time.Now()
			signals := claudeExtraUsageSignals(now, nil)
			manager, executor, _ := newClaudeExtraUsageTestManager(t, model, "block", map[string]map[string]string{
				"cred-a": signals,
				"cred-b": signals,
			})

			_, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, cliproxyexecutor.Options{})
			if len(executor.Calls()) != 0 {
				t.Fatalf("executor called %v, want no upstream request", executor.Calls())
			}
			var cooldown *modelCooldownError
			if !errors.As(errInvoke, &cooldown) || cooldown == nil {
				t.Fatalf("error = %v (%T), want *modelCooldownError", errInvoke, errInvoke)
			}
			if cooldown.StatusCode() != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", cooldown.StatusCode())
			}
			headers := cooldown.Headers()
			retryAfter, errAtoi := strconv.Atoi(headers.Get("Retry-After"))
			if errAtoi != nil || retryAfter < int((2*time.Hour-time.Minute).Seconds()) || retryAfter > int((2*time.Hour).Seconds()) {
				t.Fatalf("Retry-After = %q, want about two hours", headers.Get("Retry-After"))
			}
			if headers.Get("Anthropic-Ratelimit-Unified-Status") != "rejected" ||
				headers.Get("Anthropic-Ratelimit-Unified-5h-Status") != "rejected" ||
				headers.Get("Anthropic-Ratelimit-Unified-Overage-Status") != "rejected" ||
				headers.Get("Anthropic-Ratelimit-Unified-Overage-Reset") != "" {
				t.Fatalf("headers = %v, want a plan-limit rejection without overage", headers)
			}
		})
	}
}

func TestClaudeExtraUsageAllowAndCountTokensAreUnaffected(t *testing.T) {
	now := time.Now()
	signals := map[string]map[string]string{"cred-a": claudeExtraUsageSignals(now, nil)}

	manager, _, _ := newClaudeExtraUsageTestManager(t, "claude-extra-usage-allow", "", signals)
	payload, errInvoke := invokeAfterAuthMode(manager, "claude", "claude-extra-usage-allow", "execute", cliproxyexecutor.Options{})
	if errInvoke != nil || string(payload) != "ok:cred-a" {
		t.Fatalf("default policy: payload = %q, error = %v, want ok:cred-a", payload, errInvoke)
	}

	// Token counting is not billed, so a block never applies to it.
	manager, _, _ = newClaudeExtraUsageTestManager(t, "claude-extra-usage-count", "block", signals)
	payload, errInvoke = invokeAfterAuthMode(manager, "claude", "claude-extra-usage-count", "count", cliproxyexecutor.Options{})
	if errInvoke != nil || string(payload) != "count:cred-a" {
		t.Fatalf("count: payload = %q, error = %v, want count:cred-a", payload, errInvoke)
	}
}

func TestClaudeExtraUsageModelSnapshotBlocksOnlyThatModel(t *testing.T) {
	now := time.Now()
	opusSignals := claudeExtraUsageSignals(now, map[string]string{
		"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
		"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
	})
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
	auth := &Auth{
		ID:          "cred-a",
		Provider:    "claude",
		Quota:       QuotaState{Signals: opusSignals},
		ModelStates: map[string]*ModelState{"claude-opus-test": {Quota: QuotaState{Signals: opusSignals}}},
	}
	if errRefuse := manager.claudeExtraUsageRefusal(auth, "claude-opus-test", "claude-opus-test", now); !isCredentialTerminatedError(errRefuse) {
		t.Fatalf("opus refusal = %v, want credential refusal", errRefuse)
	}
	if errRefuse := manager.claudeExtraUsageRefusal(auth, "claude-sonnet-test", "claude-sonnet-test", now); errRefuse != nil {
		t.Fatalf("sonnet refusal = %v, want none", errRefuse)
	}

	// A shared 5h block must not hide the model's longer weekly block.
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	auth.Quota.Signals = claudeExtraUsageSignals(now, map[string]string{
		"Anthropic-Ratelimit-Unified-Reset":    at(time.Hour),
		"Anthropic-Ratelimit-Unified-5h-Reset": at(time.Hour),
	})
	auth.ModelStates["claude-opus-test"].Quota.Signals = claudeExtraUsageSignals(now, map[string]string{
		"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
		"Anthropic-Ratelimit-Unified-Reset":                at(6 * 24 * time.Hour),
		"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
	})
	var refusal *credentialTerminatedError
	if !errors.As(manager.claudeExtraUsageRefusal(auth, "claude-opus-test", "claude-opus-test", now), &refusal) || (refusal.recoverAt.Sub(now)-6*24*time.Hour).Abs() > time.Second {
		t.Fatalf("opus refusal = %+v, want recovery in 6 days", refusal)
	}
	if !errors.As(manager.claudeExtraUsageRefusal(auth, "claude-sonnet-test", "claude-sonnet-test", now), &refusal) || (refusal.recoverAt.Sub(now)-time.Hour).Abs() > time.Second {
		t.Fatalf("sonnet refusal = %+v, want recovery in 1 hour", refusal)
	}
}

func TestClaudeExtraUsageAllRefusedReportsEarliestReset(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		for _, soonFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/soon-first=%t", mode, soonFirst), func(t *testing.T) {
				model := fmt.Sprintf("claude-extra-usage-earliest-%s-%t", mode, soonFirst)
				now := time.Now()
				at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
				soon := claudeExtraUsageSignals(now, map[string]string{
					"Anthropic-Ratelimit-Unified-Reset":    at(10 * time.Minute),
					"Anthropic-Ratelimit-Unified-5h-Reset": at(10 * time.Minute),
				})
				late := claudeExtraUsageSignals(now, map[string]string{
					"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day",
					"Anthropic-Ratelimit-Unified-Reset":                at(5 * 24 * time.Hour),
					"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
					"Anthropic-Ratelimit-Unified-7d-Status":            "rejected",
					"Anthropic-Ratelimit-Unified-7d-Reset":             at(5 * 24 * time.Hour),
				})
				signals := map[string]map[string]string{"cred-a": late, "cred-b": soon}
				if soonFirst {
					signals = map[string]map[string]string{"cred-a": soon, "cred-b": late}
				}
				manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", signals)

				_, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, cliproxyexecutor.Options{})
				var cooldown *modelCooldownError
				if !errors.As(errInvoke, &cooldown) || cooldown == nil {
					t.Fatalf("error = %v (%T), want *modelCooldownError", errInvoke, errInvoke)
				}
				retryAfter, errAtoi := strconv.Atoi(cooldown.Headers().Get("Retry-After"))
				if errAtoi != nil || retryAfter > int((10*time.Minute).Seconds()) || retryAfter < int((9*time.Minute).Seconds()) {
					t.Fatalf("Retry-After = %q, want the earliest reset (~10m)", cooldown.Headers().Get("Retry-After"))
				}
			})
		}
	}
}

// claudeExtraUsageHomeDispatcher hands out Claude credentials carrying the
// rate-limit headers observed on their last response.
type claudeExtraUsageHomeDispatcher struct {
	mu      sync.Mutex
	authIDs []string
	signals map[string]map[string]string
	// cooldownAfter makes the first dispatch that excludes this credential report
	// a short Home cooldown instead of the next credential.
	cooldownAfter string
	cooledOnce    bool
	metadata      map[string]map[string]any
	// sequence, when set, dispatches these IDs in order regardless of
	// exclusions, repeating the last one, like a legacy Home.
	sequence []string
	calls    int
}

func (*claudeExtraUsageHomeDispatcher) HeartbeatOK() bool { return true }

func (*claudeExtraUsageHomeDispatcher) AbortAmbiguousDispatch() {}

func (d *claudeExtraUsageHomeDispatcher) RPopAuth(ctx context.Context, model string, sessionID string, headers http.Header, count int) ([]byte, error) {
	return d.RPopAuthWithConstraints(ctx, model, sessionID, headers, count, nil, "")
}

func (d *claudeExtraUsageHomeDispatcher) RPopAuthWithConstraints(_ context.Context, _ string, _ string, _ http.Header, _ int, excludedAuthIDs []string, _ string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	excluded := make(map[string]struct{}, len(excludedAuthIDs))
	for _, authID := range excludedAuthIDs {
		excluded[authID] = struct{}{}
	}
	if len(d.sequence) > 0 {
		authID := d.sequence[min(d.calls, len(d.sequence)-1)]
		d.calls++
		return json.Marshal(homeAuthDispatchResponse{Auth: Auth{
			ID:       authID,
			Provider: "claude",
			Status:   StatusActive,
			Metadata: d.metadata[authID],
			Quota:    QuotaState{Signals: d.signals[authID]},
		}})
	}
	if _, ok := excluded[d.cooldownAfter]; ok && !d.cooledOnce {
		d.cooledOnce = true
		return []byte(`{"error":{"type":"model_cooldown","message":"credential is cooling down","retryable":true,"retry_after_ms":20,"request_retry":2}}`), nil
	}
	for _, authID := range d.authIDs {
		if _, ok := excluded[authID]; ok {
			continue
		}
		return json.Marshal(homeAuthDispatchResponse{Auth: Auth{
			ID:       authID,
			Provider: "claude",
			Status:   StatusActive,
			Metadata: d.metadata[authID],
			Quota:    QuotaState{Signals: d.signals[authID]},
		}})
	}
	return nil, home.ErrAuthNotFound
}

func TestClaudeExtraUsageHomeModeBlocksExecutionButNotTokenCounting(t *testing.T) {
	for _, mode := range []string{"execute", "count"} {
		t.Run(mode, func(t *testing.T) {
			executor := &afterAuthTestExecutor{id: "claude"}
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{
				Home:   internalconfig.HomeConfig{Enabled: true},
				Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"},
			})
			manager.SetRetryConfig(2, 0, 5)
			manager.RegisterExecutor(executor)
			dispatcher := &claudeExtraUsageHomeDispatcher{
				authIDs: []string{"cred-a", "cred-b"},
				signals: map[string]map[string]string{"cred-a": claudeExtraUsageSignals(time.Now(), nil)},
			}
			manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)

			payload, errInvoke := invokeAfterAuthMode(manager, "claude", "claude-extra-usage-home-"+mode, mode, cliproxyexecutor.Options{})
			if errInvoke != nil {
				t.Fatalf("invoke error = %v", errInvoke)
			}
			want, wantCalls := "ok:cred-b", []string{"cred-b"}
			if mode == "count" {
				want, wantCalls = "count:cred-a", []string{"cred-a"}
			}
			if string(payload) != want || !reflect.DeepEqual(executor.Calls(), wantCalls) {
				t.Fatalf("payload = %q, calls = %v, want %q via %v", payload, executor.Calls(), want, wantCalls)
			}
		})
	}
}

func TestClaudeExtraUsageRefusalYieldsToShorterCooldown(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-short-cooldown-" + mode
			now := time.Now()
			manager, executor, _ := newClaudeExtraUsageTestManager(t, model, "block", map[string]map[string]string{
				"cred-a": claudeExtraUsageSignals(now, nil),
			})
			// cred-b is healthy but briefly cooling down after an ordinary rate limit.
			// Without waiting for it, the request must report cred-b's short cooldown
			// rather than cred-a's plan reset hours away.
			manager.SetRetryConfig(2, 0, 0)
			manager.MarkResult(WithSkipPersist(t.Context()), Result{
				AuthID:     "cred-b",
				Provider:   "claude",
				Model:      model,
				RouteModel: model,
				Error:      &Error{Code: "rate_limit", Message: "slow down", HTTPStatus: http.StatusTooManyRequests, Retryable: true},
			})

			_, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, cliproxyexecutor.Options{})
			var cooldown *modelCooldownError
			if !errors.As(errInvoke, &cooldown) || cooldown == nil {
				t.Fatalf("error = %v (%T), want *modelCooldownError", errInvoke, errInvoke)
			}
			if cooldown.resetIn <= 0 || cooldown.resetIn > time.Minute {
				t.Fatalf("reported reset in %v, want cred-b's short cooldown", cooldown.resetIn)
			}
			if len(executor.Calls()) != 0 {
				t.Fatalf("executor calls = %v, want none", executor.Calls())
			}
		})
	}
}

func TestClaudeExtraUsageBlockedThreadOwnerAsksForReplay(t *testing.T) {
	const model = "claude-extra-usage-thread"
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			caller := t.Name() + "-" + uuid.NewString()
			msgID := "msg_thread_" + uuid.NewString()
			manager := NewManager(nil, &RoundRobinSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
			manager.SetRetryConfig(0, 0, 0)
			owner, other := registerClaudeThreadTestAuths(t, manager, caller, model)
			ownerCopy := owner.Clone()
			ownerCopy.Quota.Signals = claudeExtraUsageSignals(time.Now(), nil)
			if _, errUpd := manager.Update(WithSkipPersist(t.Context()), ownerCopy); errUpd != nil {
				t.Fatal(errUpd)
			}
			var calls []string
			manager.RegisterExecutor(&claudeThreadTestExecutor{
				executeFunc: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
					calls = append(calls, auth.ID)
					return cliproxyexecutor.Response{Payload: []byte(`{"id":"msg_ok"}`)}, nil
				},
				streamFunc: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
					calls = append(calls, auth.ID)
					ch := make(chan cliproxyexecutor.StreamChunk, 1)
					ch <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"type":"message_stop"}` + "\n\n")}
					close(ch)
					return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
				},
			})
			opts := cliproxyexecutor.Options{
				SourceFormat: sdktranslator.FormatClaude,
				Stream:       stream,
				Metadata:     map[string]any{cliproxyexecutor.CallerScopeMetadataKey: caller},
			}
			cliproxysession.RememberClaudeThreadAuth(cliproxysession.ClaudeThreadCallerScope("", opts.Metadata), msgID, owner.ID)
			req := cliproxyexecutor.Request{
				Model:   model,
				Payload: []byte(`{"model":"` + model + `","thread":{"type":"continue","previous_message_id":"` + msgID + `"},"messages":[{"role":"user","content":"next"}]}`),
			}

			var errExec error
			if stream {
				errExec = executeStreamToResult(WithSkipPersist(t.Context()), manager, req, opts)
			} else {
				_, errExec = manager.Execute(WithSkipPersist(t.Context()), []string{"claude"}, req, opts)
			}
			if !clienterror.IsClaudeThreadNotFound(statusCodeFromError(errExec), errExec) {
				t.Fatalf("error = %v (status %d), want thread_not_found replay", errExec, statusCodeFromError(errExec))
			}
			if len(calls) != 0 {
				t.Fatalf("executor calls = %v (other=%s), want none", calls, other.ID)
			}
		})
	}
}

func TestClaudeExtraUsageHomeRefusalYieldsToShorterHomeCooldown(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			executor := &afterAuthTestExecutor{id: "claude"}
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{
				Home:   internalconfig.HomeConfig{Enabled: true},
				Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"},
			})
			manager.SetRetryConfig(2, 5*time.Second, 0)
			manager.RegisterExecutor(executor)
			manager.PublishHomeDispatch(&claudeExtraUsageHomeDispatcher{
				authIDs:       []string{"cred-a", "cred-b"},
				signals:       map[string]map[string]string{"cred-a": claudeExtraUsageSignals(time.Now(), nil)},
				cooldownAfter: "cred-a",
			}, executionregistry.New(), 1)

			payload, errInvoke := invokeAfterAuthMode(manager, "claude", "claude-extra-usage-home-cooldown-"+mode, mode, cliproxyexecutor.Options{})
			if errInvoke != nil || string(payload) != "ok:cred-b" {
				t.Fatalf("payload = %q, error = %v, want ok:cred-b after the short Home cooldown", payload, errInvoke)
			}
			if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-b"}) {
				t.Fatalf("executor calls = %v, want [cred-b]", calls)
			}
		})
	}
}

func TestRequestRefusedCredentialsDoNotAuthorizeRetryRounds(t *testing.T) {
	const provider, model = "refused-retry-provider", "refused-retry-model"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	for _, auth := range []*Auth{
		{ID: "refused-a", Provider: provider, Status: StatusActive},
		{ID: "no-retry-b", Provider: provider, Status: StatusActive, Metadata: map[string]any{"request_retry": 0}},
	} {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
		id := auth.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, errReg := manager.Register(WithSkipPersist(t.Context()), auth); errReg != nil {
			t.Fatal(errReg)
		}
	}
	eligibility := authSelectionEligibilityForRequest(t.Context(), cliproxyexecutor.Options{})
	if !manager.retryAllowedForRequest(t.Context(), 0, []string{provider}, model, eligibility, "", 2) {
		t.Fatal("retry not allowed without refusals, want allowed through refused-a's budget")
	}
	ctx := withRequestRefusedAuths(t.Context())
	recordRequestRefusedAuth(ctx, "refused-a")
	if manager.retryAllowedForRequest(ctx, 0, []string{provider}, model, eligibility, "", 2) {
		t.Fatal("retry allowed although the only credential with retry budget was refused for this request")
	}
}

// claudeHeadersContext returns an attempt context whose response headers arrive
// now, so tests can control arrival order independently of recording order.
func claudeHeadersContext(t *testing.T, signals map[string]string) context.Context {
	t.Helper()
	ctx := internallogging.WithFreshResponseHeadersHolder(WithSkipPersist(t.Context()))
	headers := http.Header{}
	for key, value := range signals {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)
	return ctx
}

func TestClaudeExtraUsageSnapshotsFollowHeaderArrival(t *testing.T) {
	const model = "claude-extra-usage-arrival"
	now := time.Now()
	allowed := map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed", "Anthropic-Ratelimit-Unified-5h-Status": "allowed"}
	record := func(manager *Manager, ctx context.Context, executionSeq uint64) {
		manager.MarkResult(ctx, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true, ExecutionSeq: executionSeq})
	}
	refused := func(manager *Manager) bool {
		auth, _ := manager.GetByID("cred-a")
		return manager.claudeExtraUsageRefusal(auth, model, model, time.Now()) != nil
	}

	t.Run("stream that started before the crossing ends late", func(t *testing.T) {
		manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
		streamCtx := claudeHeadersContext(t, allowed)                             // dispatched 1, headers first
		crossingCtx := claudeHeadersContext(t, claudeExtraUsageSignals(now, nil)) // dispatched 2, headers second
		record(manager, crossingCtx, 2)
		record(manager, streamCtx, 1)
		if !refused(manager) {
			t.Fatal("a stale stream completion lifted the block")
		}
		// A response from the next 5h window lifts the block.
		nextWindow := map[string]string{
			"Anthropic-Ratelimit-Unified-Status":    "allowed",
			"Anthropic-Ratelimit-Unified-5h-Status": "allowed",
			"Anthropic-Ratelimit-Unified-5h-Reset":  strconv.FormatInt(now.Add(7*time.Hour).Unix(), 10),
		}
		record(manager, claudeHeadersContext(t, nextWindow), 3)
		if refused(manager) {
			t.Fatal("a response from the next plan window did not lift the block")
		}
	})

	t.Run("request dispatched first crosses the limit last", func(t *testing.T) {
		manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
		laterCtx := claudeHeadersContext(t, allowed)                             // dispatched 2, headers first
		stalledCtx := claudeHeadersContext(t, claudeExtraUsageSignals(now, nil)) // dispatched 1, headers second
		record(manager, laterCtx, 2)
		record(manager, stalledCtx, 1)
		if !refused(manager) {
			t.Fatal("the crossing response was discarded because its request was dispatched first")
		}
	})
}

func TestClaudeExtraUsageBlockAppliesToInferenceVerification(t *testing.T) {
	const model = "claude-extra-usage-verify"
	manager, executor, _ := newClaudeExtraUsageTestManager(t, model, "block", map[string]map[string]string{
		"cred-a": claudeExtraUsageSignals(time.Now(), nil),
	})
	_, errVerify := manager.VerifyInference(t.Context(), "cred-a", model)
	var cooldown *modelCooldownError
	if !errors.As(errVerify, &cooldown) || cooldown == nil || cooldown.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("VerifyInference error = %v (%T), want a 429 cooldown", errVerify, errVerify)
	}
	if len(executor.Calls()) != 0 {
		t.Fatalf("executor calls = %v, want none", executor.Calls())
	}
	// An unblocked credential still reaches the upstream.
	_, _ = manager.VerifyInference(t.Context(), "cred-b", model)
	if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-b"}) {
		t.Fatalf("executor calls = %v, want [cred-b]", calls)
	}
}

func TestClaudeExtraUsageCredentialFailureKeepsSnapshotOrder(t *testing.T) {
	const model = "claude-extra-usage-isolated"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	staleCtx := claudeHeadersContext(t, map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed"})
	crossingCtx := claudeHeadersContext(t, claudeExtraUsageSignals(now, nil))

	manager.MarkResult(crossingCtx, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true, ExecutionSeq: 3})
	// A delayed credential-level failure without model fields rebuilds the credential quota.
	manager.MarkResult(WithSkipPersist(t.Context()), Result{AuthID: "cred-a", Provider: "claude", CredentialScope: true, ExecutionSeq: 2,
		Error: &Error{Code: "unavailable", Message: "upstream unavailable", HTTPStatus: http.StatusServiceUnavailable}})
	// An older stream then finishes with headers from before the limit was crossed.
	manager.MarkResult(staleCtx, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true, ExecutionSeq: 1})

	auth, _ := manager.GetByID("cred-a")
	if errRefuse := manager.claudeExtraUsageRefusal(auth, "claude-extra-usage-other-model", "claude-extra-usage-other-model", time.Now()); errRefuse == nil {
		t.Fatalf("shared block lifted by a stale completion after a credential-level failure; signals = %v", auth.Quota.Signals)
	}
}

// claudeHeaderTestExecutor answers like afterAuthTestExecutor and reports the
// rate-limit headers configured for the requested model.
type claudeHeaderTestExecutor struct {
	*afterAuthTestExecutor
	headersByModel map[string]map[string]string
}

func (e *claudeHeaderTestExecutor) setHeaders(ctx context.Context, model string) {
	headers := http.Header{}
	for key, value := range e.headersByModel[model] {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)
}

func (e *claudeHeaderTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.setHeaders(ctx, req.Model)
	return e.afterAuthTestExecutor.Execute(ctx, auth, req, opts)
}

func (e *claudeHeaderTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.setHeaders(ctx, req.Model)
	return e.afterAuthTestExecutor.ExecuteStream(ctx, auth, req, opts)
}

func TestClaudeExtraUsageBlockAppliesToOtherModelsOnTheCredential(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			sonnet, opus := "claude-extra-usage-sonnet-"+mode, "claude-extra-usage-opus-"+mode
			now := time.Now()
			executor := &claudeHeaderTestExecutor{
				afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"},
				headersByModel: map[string]map[string]string{
					opus:   {"Anthropic-Ratelimit-Unified-Status": "allowed", "Anthropic-Ratelimit-Unified-5h-Status": "allowed"},
					sonnet: claudeExtraUsageSignals(now, nil),
				},
			}
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
			manager.SetRetryConfig(2, 0, 5)
			manager.RegisterExecutor(executor)
			for _, id := range []string{"cred-a", "cred-b"} {
				registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: sonnet}, {ID: opus}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				if _, errReg := manager.Register(WithSkipPersist(t.Context()), &Auth{ID: id, Provider: "claude", Status: StatusActive}); errReg != nil {
					t.Fatal(errReg)
				}
			}

			for _, model := range []string{opus, sonnet} {
				if payload, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, cliproxyexecutor.Options{}); errInvoke != nil || string(payload) != "ok:cred-a" {
					t.Fatalf("%s: payload = %q, error = %v, want ok:cred-a", model, payload, errInvoke)
				}
			}
			// Sonnet's response showed cred-a's shared plan limit used up, so Opus must
			// move to cred-b even though Opus's own last response on cred-a was allowed.
			payload, errInvoke := invokeAfterAuthMode(manager, "claude", opus, mode, cliproxyexecutor.Options{})
			if errInvoke != nil || string(payload) != "ok:cred-b" {
				t.Fatalf("opus after the limit: payload = %q, error = %v, want ok:cred-b", payload, errInvoke)
			}
		})
	}
}

// claudeOpenStreamExecutor starts streams that stay open until release is closed,
// reporting extra-usage headers for every stream it starts.
type claudeOpenStreamExecutor struct {
	*afterAuthTestExecutor
	signals map[string]string
	release chan struct{}
}

func (e *claudeOpenStreamExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	headers := http.Header{}
	for key, value := range e.signals {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok:" + auth.ID)}
	go func() {
		<-e.release
		close(chunks)
	}()
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestClaudeExtraUsageBlockAppliesWhileTheCrossingStreamRuns(t *testing.T) {
	const model = "claude-extra-usage-open-stream"
	executor := &claudeOpenStreamExecutor{
		afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"},
		signals:               claudeExtraUsageSignals(time.Now(), nil),
		release:               make(chan struct{}),
	}
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
	manager.SetRetryConfig(2, 0, 5)
	manager.RegisterExecutor(executor)
	for _, id := range []string{"cred-a", "cred-b"} {
		registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, errReg := manager.Register(WithSkipPersist(t.Context()), &Auth{ID: id, Provider: "claude", Status: StatusActive}); errReg != nil {
			t.Fatal(errReg)
		}
	}

	stream, errStream := manager.ExecuteStream(t.Context(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errStream != nil {
		t.Fatalf("ExecuteStream() error = %v", errStream)
	}
	// The crossing stream on cred-a is still running; a new request must already avoid cred-a.
	payload, errExec := invokeAfterAuthMode(manager, "claude", model, "execute", cliproxyexecutor.Options{})
	close(executor.release)
	for range stream.Chunks {
	}
	if errExec != nil || string(payload) != "ok:cred-b" {
		t.Fatalf("request during the crossing stream: payload = %q, error = %v, want ok:cred-b", payload, errExec)
	}
}

func TestClaudeExtraUsageHomeRefusalDoesNotExtendRetryBudget(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			executor := &afterAuthTestExecutor{
				id:          "claude",
				failByAuth:  map[string]error{"cred-b": &Error{Message: "upstream unavailable", HTTPStatus: http.StatusServiceUnavailable}},
				markAttempt: map[string]bool{"cred-b": true},
			}
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{
				Home:   internalconfig.HomeConfig{Enabled: true},
				Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"},
			})
			manager.SetRetryConfig(0, 0, 0)
			manager.RegisterExecutor(executor)
			for _, sequence := range [][]string{nil, {"cred-a", "cred-b", "cred-a", "cred-b"}} {
				executor.mu.Lock()
				executor.calls = nil
				executor.mu.Unlock()
				manager.PublishHomeDispatch(&claudeExtraUsageHomeDispatcher{
					authIDs:  []string{"cred-a", "cred-b"},
					signals:  map[string]map[string]string{"cred-a": claudeExtraUsageSignals(time.Now(), nil)},
					metadata: map[string]map[string]any{"cred-a": {"request_retry": 2}, "cred-b": {"request_retry": 0}},
					sequence: sequence,
				}, executionregistry.New(), 1)

				_, _ = invokeAfterAuthMode(manager, "claude", "claude-extra-usage-home-retry-"+mode, mode, cliproxyexecutor.Options{})
				if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-b"}) {
					t.Fatalf("dispatch sequence %v: executor calls = %v, want a single attempt on cred-b", sequence, calls)
				}
			}
		})
	}
}

func TestClaudeExtraUsageFirstStreamRecordsPerModelBlock(t *testing.T) {
	const model = "claude-extra-usage-first-opus-stream"
	executor := &claudeOpenStreamExecutor{
		afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"},
		signals: claudeExtraUsageSignals(time.Now(), map[string]string{
			"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
			"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
		}),
		release: make(chan struct{}),
	}
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
	manager.SetRetryConfig(2, 0, 5)
	manager.RegisterExecutor(executor)
	for _, id := range []string{"cred-a", "cred-b"} {
		registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, errReg := manager.Register(WithSkipPersist(t.Context()), &Auth{ID: id, Provider: "claude", Status: StatusActive}); errReg != nil {
			t.Fatal(errReg)
		}
	}

	// The first request for this model on cred-a leaves its weekly window used up.
	stream, errStream := manager.ExecuteStream(t.Context(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errStream != nil {
		t.Fatalf("ExecuteStream() error = %v", errStream)
	}
	payload, errExec := invokeAfterAuthMode(manager, "claude", model, "execute", cliproxyexecutor.Options{})
	close(executor.release)
	for range stream.Chunks {
	}
	if errExec != nil || string(payload) != "ok:cred-b" {
		t.Fatalf("request during the first stream: payload = %q, error = %v, want ok:cred-b", payload, errExec)
	}
}

func TestClaudeExtraUsageStreamFromReplacedCredentialIsIgnored(t *testing.T) {
	const model = "claude-extra-usage-replaced"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	attempt, _ := manager.GetByID("cred-a")
	// The credential is replaced under the same ID while the old stream is starting.
	if _, errReg := manager.Register(WithSkipPersist(t.Context()), &Auth{ID: "cred-a", Provider: "claude", Status: StatusActive}); errReg != nil {
		t.Fatal(errReg)
	}
	replacement, _ := manager.GetByID("cred-a")
	if replacement.RegistrationEpoch <= attempt.RegistrationEpoch {
		t.Fatalf("replacement epoch %d not newer than %d", replacement.RegistrationEpoch, attempt.RegistrationEpoch)
	}
	ctx := internallogging.WithFreshResponseHeadersHolder(WithSkipPersist(t.Context()))
	manager.watchClaudeResponseHeaders(ctx, attempt, "", "claude", model, model)
	headers := http.Header{}
	for key, value := range claudeExtraUsageSignals(time.Now(), nil) {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)

	current, _ := manager.GetByID("cred-a")
	if errRefuse := manager.claudeExtraUsageRefusal(current, model, model, time.Now()); errRefuse != nil {
		t.Fatalf("old credential's stream blocked its replacement: %v", errRefuse)
	}
}

// claudeDelayedPayloadExecutor opens streams whose rate-limit headers arrive at
// once while the first payload is held until release is closed.
type claudeDelayedPayloadExecutor struct {
	*afterAuthTestExecutor
	release chan struct{}
}

func (e *claudeDelayedPayloadExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	headers := http.Header{}
	for key, value := range claudeExtraUsageSignals(time.Now(), nil) {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	go func() {
		<-e.release
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok:" + auth.ID)}
		close(chunks)
	}()
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestClaudeExtraUsageBlockAppliesBeforeTheFirstStreamPayload(t *testing.T) {
	const model = "claude-extra-usage-delayed-payload"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	executor := &claudeDelayedPayloadExecutor{afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"}, release: make(chan struct{})}
	manager.RegisterExecutor(executor)

	streamDone := make(chan error, 1)
	go func() {
		stream, errStream := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
		if errStream == nil {
			for range stream.Chunks {
			}
		}
		streamDone <- errStream
	}()

	// The block must become visible while the first payload is still held back.
	deadline := time.After(5 * time.Second)
	for {
		auth, _ := manager.GetByID("cred-a")
		if auth != nil && len(executor.Calls()) == 1 && manager.claudeExtraUsageRefusal(auth, model, model, time.Now()) != nil {
			break
		}
		select {
		case <-deadline:
			close(executor.release)
			t.Fatal("block not recorded before the stream's first payload")
		default:
			runtime.Gosched()
		}
	}
	payload, errExec := invokeAfterAuthMode(manager, "claude", model, "execute", cliproxyexecutor.Options{})
	close(executor.release)
	if errStream := <-streamDone; errStream != nil {
		t.Fatalf("crossing stream error = %v", errStream)
	}
	if errExec != nil || string(payload) != "ok:cred-b" {
		t.Fatalf("request before the first payload: payload = %q, error = %v, want ok:cred-b", payload, errExec)
	}
}

// claudeRefreshRaceExecutor answers cred-a's first request with a 401 after a
// concurrent response has recorded that cred-a is in extra usage.
type claudeRefreshRaceExecutor struct {
	*afterAuthTestExecutor
	manager   *Manager
	t         *testing.T
	model     string
	bootstrap bool
}

func (e *claudeRefreshRaceExecutor) failFirst(auth *Auth) bool {
	if auth.ID != "cred-a" || len(e.Calls()) != 0 {
		return false
	}
	e.record(auth)
	e.manager.MarkResult(claudeHeadersContext(e.t, claudeExtraUsageSignals(time.Now(), nil)), Result{
		AuthID: auth.ID, Provider: "claude", Model: e.model, RouteModel: e.model, Success: true,
		AccessToken: authAccessToken(auth), RegistrationEpoch: auth.RegistrationEpoch, CredentialVersion: auth.CredentialVersion,
	})
	return true
}

func (e *claudeRefreshRaceExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.failFirst(auth) {
		cliproxyexecutor.MarkUpstreamAttempt(ctx)
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusUnauthorized, Message: "expired token"}
	}
	return e.afterAuthTestExecutor.Execute(ctx, auth, req, opts)
}

func (e *claudeRefreshRaceExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e.failFirst(auth) {
		cliproxyexecutor.MarkUpstreamAttempt(ctx)
		unauthorized := &Error{HTTPStatus: http.StatusUnauthorized, Message: "expired token"}
		if !e.bootstrap {
			return nil, unauthorized
		}
		chunks := make(chan cliproxyexecutor.StreamChunk, 1)
		chunks <- cliproxyexecutor.StreamChunk{Err: unauthorized}
		close(chunks)
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}
	return e.afterAuthTestExecutor.ExecuteStream(ctx, auth, req, opts)
}

func (e *claudeRefreshRaceExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	refreshed := auth.Clone()
	refreshed.Metadata["access_token"] = "new-token"
	return refreshed, nil
}

func TestClaudeExtraUsageRefreshRetryHonorsBlock(t *testing.T) {
	for _, mode := range []string{"execute", "stream", "stream-bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-refresh-" + mode
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
			manager.SetRetryConfig(0, 0, 0)
			executor := &claudeRefreshRaceExecutor{afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"}, manager: manager, t: t, model: model, bootstrap: mode == "stream-bootstrap"}
			manager.RegisterExecutor(executor)
			for _, id := range []string{"cred-a", "cred-b"} {
				registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				auth := &Auth{ID: id, Provider: "claude", Status: StatusActive, Metadata: map[string]any{"access_token": "old-token", "refresh_token": "refresh-token"}}
				if _, errReg := manager.Register(WithSkipPersist(t.Context()), auth); errReg != nil {
					t.Fatal(errReg)
				}
			}

			invokeMode := mode
			if mode == "stream-bootstrap" {
				invokeMode = "stream"
			}
			payload, errInvoke := invokeAfterAuthMode(manager, "claude", model, invokeMode, cliproxyexecutor.Options{})
			if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-a", "cred-b"}) {
				t.Fatalf("executor calls = %v (payload %q, error %v), want the refreshed resend to skip blocked cred-a", calls, payload, errInvoke)
			}
			if errInvoke != nil || string(payload) != "ok:cred-b" {
				t.Fatalf("payload = %q, error = %v, want ok:cred-b", payload, errInvoke)
			}
		})
	}
}

func TestClaudeExtraUsageRefreshRetryRefusalReportsPlanLimit(t *testing.T) {
	for _, mode := range []string{"execute", "stream", "stream-bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-refresh-only-" + mode
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
			manager.SetRetryConfig(0, 0, 0)
			executor := &claudeRefreshRaceExecutor{afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"}, manager: manager, t: t, model: model, bootstrap: mode == "stream-bootstrap"}
			manager.RegisterExecutor(executor)
			registry.GetGlobalRegistry().RegisterClient("cred-a", "claude", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("cred-a") })
			auth := &Auth{ID: "cred-a", Provider: "claude", Status: StatusActive, Metadata: map[string]any{"access_token": "old-token", "refresh_token": "refresh-token"}}
			if _, errReg := manager.Register(WithSkipPersist(t.Context()), auth); errReg != nil {
				t.Fatal(errReg)
			}

			invokeMode := mode
			if mode == "stream-bootstrap" {
				invokeMode = "stream"
			}
			_, errInvoke := invokeAfterAuthMode(manager, "claude", model, invokeMode, cliproxyexecutor.Options{})
			// The refresh resolved the 401, so the client must see the plan limit, not a sign-in failure.
			var cooldown *modelCooldownError
			if !errors.As(errInvoke, &cooldown) || cooldown == nil {
				t.Fatalf("error = %v (%T), want the plan-limit 429", errInvoke, errInvoke)
			}
		})
	}
}

// claudeHeldBodyExecutor reports extra-usage headers at once and holds the rest
// of a non-streaming response, or ends a stream without a completed response.
type claudeHeldBodyExecutor struct {
	*afterAuthTestExecutor
	release chan struct{}
}

func (e *claudeHeldBodyExecutor) setHeaders(ctx context.Context) {
	headers := http.Header{}
	for key, value := range claudeExtraUsageSignals(time.Now(), nil) {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)
}

func (e *claudeHeldBodyExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if auth.ID != "cred-a" {
		return e.afterAuthTestExecutor.Execute(ctx, auth, req, opts)
	}
	e.record(auth)
	e.setHeaders(ctx)
	<-e.release
	return cliproxyexecutor.Response{Payload: []byte("ok:" + auth.ID)}, nil
}

func (e *claudeHeldBodyExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	e.setHeaders(ctx)
	chunks := make(chan cliproxyexecutor.StreamChunk)
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestClaudeExtraUsageBlockAppliesWhileANonStreamingResponseIsBuffered(t *testing.T) {
	const model = "claude-extra-usage-buffered"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	executor := &claudeHeldBodyExecutor{afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"}, release: make(chan struct{})}
	manager.RegisterExecutor(executor)

	firstDone := make(chan error, 1)
	go func() {
		_, errExec := manager.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
		firstDone <- errExec
	}()
	deadline := time.After(5 * time.Second)
	for {
		auth, _ := manager.GetByID("cred-a")
		if auth != nil && manager.claudeExtraUsageRefusal(auth, model, model, time.Now()) != nil {
			break
		}
		select {
		case <-deadline:
			close(executor.release)
			t.Fatal("block not recorded while the crossing response body was still being read")
		default:
			runtime.Gosched()
		}
	}
	payload, errExec := invokeAfterAuthMode(manager, "claude", model, "execute", cliproxyexecutor.Options{})
	close(executor.release)
	if errFirst := <-firstDone; errFirst != nil {
		t.Fatalf("crossing request error = %v", errFirst)
	}
	if errExec != nil || string(payload) != "ok:cred-b" {
		t.Fatalf("request during the crossing response: payload = %q, error = %v, want ok:cred-b", payload, errExec)
	}
}

func TestClaudeExtraUsageIncompleteVerificationRecordsBlock(t *testing.T) {
	const model = "claude-extra-usage-verify-incomplete"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	executor := &claudeHeldBodyExecutor{afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"}, release: make(chan struct{})}
	manager.RegisterExecutor(executor)

	if _, errVerify := manager.VerifyInference(t.Context(), "cred-a", model); errVerify == nil {
		t.Fatal("VerifyInference() succeeded, want an incomplete-response error")
	}
	auth, _ := manager.GetByID("cred-a")
	if errRefuse := manager.claudeExtraUsageRefusal(auth, model, model, time.Now()); errRefuse == nil {
		t.Fatalf("incomplete verification lost its extra-usage headers; signals = %v", auth.Quota.Signals)
	}
}

func TestClaudeExtraUsageSnapshotChoiceFollowsHeaderArrival(t *testing.T) {
	const model = "claude-extra-usage-snapshot-choice"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	live, _ := manager.GetByID("cred-a")
	// The crossing headers arrived last (stamp 20) but were recorded first.
	manager.observeClaudeResponseHeaders(Result{AuthID: "cred-a", RegistrationEpoch: live.RegistrationEpoch, CredentialVersion: live.CredentialVersion},
		"claude", model, model, http.Header{
			"Anthropic-Ratelimit-Unified-Status":         {"rejected"},
			"Anthropic-Ratelimit-Unified-5h-Status":      {"rejected"},
			"Anthropic-Ratelimit-Unified-Overage-Status": {"allowed"},
			"Anthropic-Ratelimit-Unified-Reset":          {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		}, 20)
	// A scheduler copy holds an older response (stamp 19) that was recorded later.
	stale := QuotaState{
		Signals:     map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed"},
		ObservedAt:  time.Now().Add(time.Minute),
		observedSeq: 19,
	}
	picked := live.Clone()
	picked.Quota = stale
	picked.ModelStates = map[string]*ModelState{model: {Status: StatusActive, Quota: stale}}
	if errRefuse := manager.claudeExtraUsageRefusal(picked, model, model, time.Now()); errRefuse == nil {
		t.Fatal("an older response recorded later hid the newer extra-usage snapshot")
	}
}

func TestClaudeExtraUsageBlockRecordedDuringAfterAuthInterceptorIsHonored(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-interceptor-" + mode
			manager, executor, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
			opts := cliproxyexecutor.Options{
				RequestAfterAuthInterceptor: func(_ context.Context, req cliproxyexecutor.RequestAfterAuthInterceptRequest) cliproxyexecutor.RequestAfterAuthInterceptResponse {
					if authID, _ := req.Metadata[cliproxyexecutor.SelectedAuthMetadataKey].(string); authID == "cred-a" {
						// Another response on cred-a crosses the limit while the plugin runs.
						live, _ := manager.GetByID("cred-a")
						manager.observeClaudeResponseHeaders(Result{AuthID: "cred-a", RegistrationEpoch: live.RegistrationEpoch, CredentialVersion: live.CredentialVersion},
							"claude", model, model, http.Header{
								"Anthropic-Ratelimit-Unified-Status":         {"rejected"},
								"Anthropic-Ratelimit-Unified-5h-Status":      {"rejected"},
								"Anthropic-Ratelimit-Unified-Overage-Status": {"allowed"},
								"Anthropic-Ratelimit-Unified-Reset":          {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
							}, 1<<62)
					}
					return cliproxyexecutor.RequestAfterAuthInterceptResponse{}
				},
			}
			payload, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, opts)
			if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-b"}) {
				t.Fatalf("executor calls = %v (payload %q, error %v), want only cred-b", calls, payload, errInvoke)
			}
		})
	}
}

func TestClaudeExtraUsageModelBlockSurvivesCooldownUnwrap(t *testing.T) {
	const model = "claude-extra-usage-unwrap-opus"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	allowed := map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed"}
	minute, fiveSeconds := time.Minute, 5*time.Second

	// An independent model failure is live when a credential-wide quota wraps it.
	manager.MarkResult(claudeHeadersContext(t, allowed), Result{AuthID: "cred-a", Provider: "claude", Model: model,
		Error: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "capacity"}, RetryAfter: &minute})
	manager.MarkResult(claudeHeadersContext(t, map[string]string{"Retry-After": "5"}), Result{AuthID: "cred-a", Provider: "claude",
		Model: "claude-extra-usage-unwrap-sonnet", CredentialScope: true, Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"}, RetryAfter: &fiveSeconds})
	// An older attempt got allowed headers; its result is recorded later.
	delayed := claudeHeadersContext(t, allowed)
	// A request already sent crosses the model's weekly limit; its headers arrive now.
	attempt, _ := manager.GetByID("cred-a")
	crossing := internallogging.WithFreshResponseHeadersHolder(WithSkipPersist(t.Context()))
	manager.watchClaudeResponseHeaders(crossing, attempt, "", "claude", model, model)
	headers := http.Header{}
	for key, value := range claudeExtraUsageSignals(time.Now(), map[string]string{
		"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
		"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
	}) {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(crossing, headers)
	before, _ := manager.GetByID("cred-a")
	if before.ModelStates[model].credentialQuotaShadow == nil || manager.claudeExtraUsageRefusal(before, model, model, time.Now()) == nil {
		t.Fatal("setup: want a wrapped model state that is blocked")
	}

	// The credential wrap expires, then the older result unwraps the model state.
	manager.mu.Lock()
	manager.auths["cred-a"].Quota.NextRecoverAt = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.MarkResult(delayed, Result{AuthID: "cred-a", Provider: "claude", Model: model,
		Error: &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "capacity"}, RetryAfter: &minute})
	after, _ := manager.GetByID("cred-a")
	if manager.claudeExtraUsageRefusal(after, model, model, time.Now()) == nil {
		t.Fatalf("the cooldown unwrap rolled back the newer model block; model signals = %v", after.ModelStates[model].Quota.Signals)
	}
}

func TestClaudeExtraUsageNeverRefusesAPIKeyCredentials(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
	signals := claudeExtraUsageSignals(time.Now(), nil)
	apiKey := &Auth{ID: "key", Provider: "claude", Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey}, Quota: QuotaState{Signals: signals}}
	if errRefuse := manager.claudeExtraUsageRefusal(apiKey, "claude-model", "claude-model", time.Now()); errRefuse != nil {
		t.Fatalf("API-key credential refused: %v", errRefuse)
	}
	for name, seat := range map[string]*Auth{
		"oauth file":                {ID: "seat", Provider: "claude", Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}, Quota: QuotaState{Signals: signals}},
		"oauth token as an api key": {ID: "seat-key", Provider: "claude", Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey, AttributeAPIKey: "sk-ant-oat01-seat"}, Quota: QuotaState{Signals: signals}},
	} {
		if errRefuse := manager.claudeExtraUsageRefusal(seat, "claude-model", "claude-model", time.Now()); errRefuse == nil {
			t.Fatalf("%s: subscription credential not refused", name)
		}
	}
}

// claudeVerifyFallbackExecutor answers verification's stream with 501 after a
// concurrent response has recorded that cred-a is in extra usage.
type claudeVerifyFallbackExecutor struct {
	*afterAuthTestExecutor
	manager *Manager
	model   string
}

func (e *claudeVerifyFallbackExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.manager.observeClaudeResponseHeaders(Result{AuthID: auth.ID, RegistrationEpoch: auth.RegistrationEpoch, CredentialVersion: auth.CredentialVersion},
		"claude", e.model, e.model, http.Header{
			"Anthropic-Ratelimit-Unified-Status":         {"rejected"},
			"Anthropic-Ratelimit-Unified-5h-Status":      {"rejected"},
			"Anthropic-Ratelimit-Unified-Overage-Status": {"allowed"},
			"Anthropic-Ratelimit-Unified-Reset":          {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		}, 1<<62)
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Message: "streaming not supported"}
}

func TestClaudeExtraUsageVerificationFallbackHonorsBlock(t *testing.T) {
	const model = "claude-extra-usage-verify-fallback"
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	executor := &claudeVerifyFallbackExecutor{afterAuthTestExecutor: &afterAuthTestExecutor{id: "claude"}, manager: manager, model: model}
	manager.RegisterExecutor(executor)

	_, errVerify := manager.VerifyInference(t.Context(), "cred-a", model)
	var cooldown *modelCooldownError
	if !errors.As(errVerify, &cooldown) || cooldown == nil {
		t.Fatalf("VerifyInference error = %v (%T), want the plan-limit 429", errVerify, errVerify)
	}
	if calls := executor.Calls(); len(calls) != 0 {
		t.Fatalf("non-streaming fallback sent despite the block: calls = %v", calls)
	}
}

func TestClaudeExtraUsageBlockSurvivesConfigCredentialReload(t *testing.T) {
	const model = "claude-extra-usage-reload"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
	configSeat := func(priority string) *Auth {
		return &Auth{ID: "seat", Provider: "claude", Status: StatusActive, Attributes: map[string]string{
			AttributeAuthKind: AuthKindAPIKey, AttributeAPIKey: "sk-ant-oat01-seat", "priority": priority,
		}}
	}
	registry.GetGlobalRegistry().RegisterClient("seat", "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("seat") })
	if _, errReg := manager.Register(WithSkipPersist(t.Context()), configSeat("0")); errReg != nil {
		t.Fatal(errReg)
	}
	live, _ := manager.GetByID("seat")
	manager.observeClaudeResponseHeaders(Result{AuthID: "seat", RegistrationEpoch: live.RegistrationEpoch, CredentialVersion: live.CredentialVersion},
		"claude", "claude-extra-usage-reload-other", "claude-extra-usage-reload-other", http.Header{
			"Anthropic-Ratelimit-Unified-Status":         {"rejected"},
			"Anthropic-Ratelimit-Unified-5h-Status":      {"rejected"},
			"Anthropic-Ratelimit-Unified-Overage-Status": {"allowed"},
			"Anthropic-Ratelimit-Unified-Reset":          {strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		}, 1<<62)

	// A config reload rebuilds the same credential with a new priority.
	if _, errUpd := manager.Update(WithSkipPersist(t.Context()), configSeat("5")); errUpd != nil {
		t.Fatal(errUpd)
	}
	reloaded, _ := manager.GetByID("seat")
	if errRefuse := manager.claudeExtraUsageRefusal(reloaded, model, model, time.Now()); errRefuse == nil {
		t.Fatalf("config reload erased the shared block; signals = %v", reloaded.Quota.Signals)
	}
	// New credentials under the same ID do not inherit the credential-level snapshot.
	replaced := configSeat("5")
	replaced.Attributes[AttributeAPIKey] = "sk-ant-oat01-other-seat"
	if _, errUpd := manager.Update(WithSkipPersist(t.Context()), replaced); errUpd != nil {
		t.Fatal(errUpd)
	}
	other, _ := manager.GetByID("seat")
	if errRefuse := manager.claudeExtraUsageRefusal(other, model, model, time.Now()); errRefuse != nil {
		t.Fatalf("a different credential inherited the old block: %v", errRefuse)
	}
}

func TestClaudeExtraUsageModelBlockSurvivesCredentialUpdates(t *testing.T) {
	const opus = "claude-extra-usage-update-opus"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"}})
	seat := func() *Auth {
		return &Auth{ID: "seat", Provider: "claude", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}}
	}
	registry.GetGlobalRegistry().RegisterClient("seat", "claude", []*registry.ModelInfo{{ID: opus}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("seat") })
	if _, errReg := manager.Register(WithSkipPersist(t.Context()), seat()); errReg != nil {
		t.Fatal(errReg)
	}
	live, _ := manager.GetByID("seat")
	manager.observeClaudeResponseHeaders(Result{AuthID: "seat", RegistrationEpoch: live.RegistrationEpoch, CredentialVersion: live.CredentialVersion},
		"claude", opus, opus, http.Header{
			"Anthropic-Ratelimit-Unified-Status":               {"rejected"},
			"Anthropic-Ratelimit-Unified-Representative-Claim": {"seven_day_opus"},
			"Anthropic-Ratelimit-Unified-Overage-Status":       {"allowed"},
			"Anthropic-Ratelimit-Unified-Reset":                {strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10)},
		}, 1<<62)
	refused := func(step string) {
		t.Helper()
		current, _ := manager.GetByID("seat")
		if manager.claudeExtraUsageRefusal(current, opus, opus, time.Now()) == nil {
			t.Fatalf("%s erased the per-model block", step)
		}
	}
	refused("setup")

	// An update that brings its own, older model states.
	stale := seat()
	stale.ModelStates = map[string]*ModelState{opus: {Status: StatusActive, Quota: QuotaState{
		Signals: map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed"}, ObservedAt: time.Now().Add(-time.Hour),
	}}}
	if _, errUpd := manager.Update(WithSkipPersist(t.Context()), stale); errUpd != nil {
		t.Fatal(errUpd)
	}
	refused("an update with older model states")

	// Disabling and re-enabling through rebuilt records.
	disabled := seat()
	disabled.Disabled, disabled.Status = true, StatusDisabled
	if _, errUpd := manager.Update(WithSkipPersist(t.Context()), disabled); errUpd != nil {
		t.Fatal(errUpd)
	}
	if _, errUpd := manager.Update(WithSkipPersist(t.Context()), seat()); errUpd != nil {
		t.Fatal(errUpd)
	}
	refused("a disable and re-enable")
}

// claudeWeeklyOpusExecutor reports a per-model weekly window in extra usage.
type claudeWeeklyOpusExecutor struct {
	*afterAuthTestExecutor
}

func (e *claudeWeeklyOpusExecutor) setHeaders(ctx context.Context) {
	headers := http.Header{}
	for key, value := range claudeExtraUsageSignals(time.Now(), map[string]string{
		"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
		"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
	}) {
		headers.Set(key, value)
	}
	internallogging.SetResponseHeaders(ctx, headers)
}

func (e *claudeWeeklyOpusExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.setHeaders(ctx)
	return e.afterAuthTestExecutor.Execute(ctx, auth, req, opts)
}

func (e *claudeWeeklyOpusExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.setHeaders(ctx)
	return e.afterAuthTestExecutor.ExecuteStream(ctx, auth, req, opts)
}

func TestClaudeExtraUsagePerModelBlockAppliesToPrefixedAliases(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			const route = "tenant/opus"
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetConfig(&internalconfig.Config{
				Claude: internalconfig.ClaudeConfig{ExtraUsage: "block"},
				ClaudeKey: []internalconfig.ClaudeKey{{APIKey: "sk-ant-oat01-alias-seat", Prefix: "tenant",
					Models: []internalconfig.ClaudeModel{{Name: "claude-opus-4-6", Alias: "opus"}}}},
			})
			executor := &claudeWeeklyOpusExecutor{&afterAuthTestExecutor{id: "claude"}}
			manager.RegisterExecutor(executor)
			registry.GetGlobalRegistry().RegisterClient("alias-seat", "claude", []*registry.ModelInfo{{ID: route}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("alias-seat") })
			seat := &Auth{ID: "alias-seat", Provider: "claude", Prefix: "tenant", Status: StatusActive,
				Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey, AttributeAPIKey: "sk-ant-oat01-alias-seat"}}
			if _, errReg := manager.Register(WithSkipPersist(t.Context()), seat); errReg != nil {
				t.Fatal(errReg)
			}

			if _, errInvoke := invokeAfterAuthMode(manager, "claude", route, mode, cliproxyexecutor.Options{}); errInvoke != nil {
				t.Fatalf("crossing request error = %v", errInvoke)
			}
			calls := len(executor.Calls())
			_, errInvoke := invokeAfterAuthMode(manager, "claude", route, mode, cliproxyexecutor.Options{})
			var cooldown *modelCooldownError
			if !errors.As(errInvoke, &cooldown) || len(executor.Calls()) != calls {
				t.Fatalf("per-model block missed for %s: upstream calls %d -> %d, error = %v", route, calls, len(executor.Calls()), errInvoke)
			}
		})
	}
}

func TestClaudeExtraUsageSameWindowAllowedResponseKeepsBlock(t *testing.T) {
	const model = "claude-extra-usage-same-window"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	reset := strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10)
	refused := func() bool {
		auth, _ := manager.GetByID("cred-a")
		return manager.claudeExtraUsageRefusal(auth, model, model, time.Now()) != nil
	}
	// Request A was admitted just before the limit was crossed and returns late;
	// request B crossed it and its headers arrived first.
	admittedBefore := claudeHeadersContext(t, nil)
	crossing := claudeHeadersContext(t, claudeExtraUsageSignals(now, nil))
	manager.MarkResult(crossing, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	internallogging.SetResponseHeaders(admittedBefore, http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"allowed_warning"},
		"Anthropic-Ratelimit-Unified-5h-Status":      {"allowed_warning"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       {reset},
		"Anthropic-Ratelimit-Unified-Overage-Status": {"allowed"},
	})
	manager.MarkResult(admittedBefore, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	if !refused() {
		t.Fatal("a same-window response admitted before the crossing lifted the block")
	}
}

func TestClaudeExtraUsagePerModelResponseKeepsSharedBlock(t *testing.T) {
	const opus, sonnet, haiku = "claude-extra-usage-keep-opus", "claude-extra-usage-keep-sonnet", "claude-extra-usage-keep-haiku"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, opus, "block", nil)
	// A Sonnet response shows the shared 5h window used up.
	manager.MarkResult(claudeHeadersContext(t, claudeExtraUsageSignals(now, nil)),
		Result{AuthID: "cred-a", Provider: "claude", Model: sonnet, RouteModel: sonnet, Success: true})
	// An Opus request admitted before that crossing returns later: 5h still allowed
	// for it, but Opus's own weekly window is in extra usage.
	manager.MarkResult(claudeHeadersContext(t, claudeExtraUsageSignals(now, map[string]string{
		"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
		"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
	})), Result{AuthID: "cred-a", Provider: "claude", Model: opus, RouteModel: opus, Success: true})

	auth, _ := manager.GetByID("cred-a")
	// Haiku has no snapshot of its own, so only the shared block can refuse it.
	if manager.claudeExtraUsageRefusal(auth, haiku, haiku, time.Now()) == nil {
		t.Fatal("a per-model extra-usage response erased the shared block")
	}
	if manager.claudeExtraUsageRefusal(auth, opus, opus, time.Now()) == nil {
		t.Fatal("Opus's own weekly block was not recorded")
	}
}

func TestClaudeExtraUsageUnifiedOnlyBlockLiftsOnLaterWindow(t *testing.T) {
	const model = "claude-extra-usage-unified-only"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	refused := func() bool {
		auth, _ := manager.GetByID("cred-a")
		return manager.claudeExtraUsageRefusal(auth, model, model, time.Now()) != nil
	}
	record := func(signals map[string]string) {
		manager.MarkResult(claudeHeadersContext(t, signals), Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	}
	// The block is known only from the unified headers.
	record(map[string]string{
		"Anthropic-Ratelimit-Unified-Status":               "rejected",
		"Anthropic-Ratelimit-Unified-Representative-Claim": "five_hour",
		"Anthropic-Ratelimit-Unified-Reset":                at(2 * time.Hour),
		"Anthropic-Ratelimit-Unified-Overage-Status":       "allowed",
	})
	if !refused() {
		t.Fatal("setup: unified-only extra usage not refused")
	}
	sameWindow := map[string]string{
		"Anthropic-Ratelimit-Unified-Status":               "allowed_warning",
		"Anthropic-Ratelimit-Unified-Representative-Claim": "five_hour",
		"Anthropic-Ratelimit-Unified-Reset":                at(2 * time.Hour),
	}
	record(sameWindow)
	if !refused() {
		t.Fatal("a same-window response lifted the block")
	}
	record(map[string]string{
		"Anthropic-Ratelimit-Unified-Status":               "allowed",
		"Anthropic-Ratelimit-Unified-Representative-Claim": "five_hour",
		"Anthropic-Ratelimit-Unified-Reset":                at(7 * time.Hour),
	})
	if refused() {
		t.Fatal("a response from the next window did not lift the block")
	}
}

func TestClaudeExtraUsageKeepRuleOnlyAppliesWhenBlocking(t *testing.T) {
	const model = "claude-extra-usage-keep-allow"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "allow", nil)
	record := func(signals map[string]string) {
		manager.MarkResult(claudeHeadersContext(t, signals), Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	}
	record(claudeExtraUsageSignals(now, nil))
	// A later real 429 with overage rejected must show up in the quota view.
	record(map[string]string{
		"Anthropic-Ratelimit-Unified-Status":         "rejected",
		"Anthropic-Ratelimit-Unified-5h-Status":      "rejected",
		"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10),
		"Anthropic-Ratelimit-Unified-Overage-Status": "rejected",
	})
	auth, _ := manager.GetByID("cred-a")
	if got := auth.Quota.Signals["Anthropic-Ratelimit-Unified-Overage-Status"]; got != "rejected" {
		t.Fatalf("allow-mode snapshot overage status = %q, want the latest response's rejected", got)
	}
}

func TestClaudeExtraUsageShorterStaleBlockDoesNotShortenLongerOne(t *testing.T) {
	const model = "claude-extra-usage-keep-longer"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	record := func(signals map[string]string) {
		manager.MarkResult(claudeHeadersContext(t, signals), Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	}
	// The 7d window is used up for five days.
	record(claudeExtraUsageSignals(now, map[string]string{
		"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day",
		"Anthropic-Ratelimit-Unified-Reset":                at(120 * time.Hour),
		"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
		"Anthropic-Ratelimit-Unified-7d-Status":            "rejected",
		"Anthropic-Ratelimit-Unified-7d-Reset":             at(120 * time.Hour),
	}))
	// A response admitted after the 5h crossing but before the 7d one arrives late.
	record(claudeExtraUsageSignals(now, map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status": "allowed",
		"Anthropic-Ratelimit-Unified-7d-Reset":  at(120 * time.Hour),
	}))
	auth, _ := manager.GetByID("cred-a")
	var refusal *credentialTerminatedError
	if !errors.As(manager.claudeExtraUsageRefusal(auth, model, model, now), &refusal) || refusal.recoverAt.Sub(now) < 119*time.Hour {
		t.Fatalf("refusal = %+v, want the five-day block kept", refusal)
	}
}

func TestClaudeExtraUsageLaterWindowFromAnotherModelLiftsSharedBlock(t *testing.T) {
	const modelX, modelY = "claude-extra-usage-lift-x", "claude-extra-usage-lift-y"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, modelX, "block", nil)
	record := func(model string, signals map[string]string) {
		manager.MarkResult(claudeHeadersContext(t, signals), Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	}
	// Model X's response shows the shared 5h window used up.
	record(modelX, claudeExtraUsageSignals(now, nil))
	// Model Y's response comes from the next 5h window.
	record(modelY, map[string]string{
		"Anthropic-Ratelimit-Unified-Status":    "allowed",
		"Anthropic-Ratelimit-Unified-5h-Status": "allowed",
		"Anthropic-Ratelimit-Unified-5h-Reset":  strconv.FormatInt(now.Add(7*time.Hour).Unix(), 10),
	})
	auth, _ := manager.GetByID("cred-a")
	if errRefuse := manager.claudeExtraUsageRefusal(auth, modelX, modelX, time.Now()); errRefuse != nil {
		t.Fatalf("model X kept a shared block after the window rolled over: %v", errRefuse)
	}
}

func TestClaudeExtraUsageBlockSurvivesOutOfOrderObserverCommits(t *testing.T) {
	now := time.Now()
	reset := strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10)
	for _, tc := range []struct {
		name     string
		crossing map[string]string
		stale    map[string]string
		checked  string
	}{
		{
			name:     "shared window",
			crossing: claudeExtraUsageSignals(now, nil),
			stale: map[string]string{
				"Anthropic-Ratelimit-Unified-Status": "allowed_warning", "Anthropic-Ratelimit-Unified-5h-Status": "allowed_warning",
				"Anthropic-Ratelimit-Unified-5h-Reset": reset,
			},
			checked: "claude-extra-usage-order-other",
		},
		{
			name: "model window",
			crossing: claudeExtraUsageSignals(now, map[string]string{
				"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
				"Anthropic-Ratelimit-Unified-5h-Status":            "allowed",
			}),
			stale: map[string]string{
				"Anthropic-Ratelimit-Unified-Status": "allowed_warning", "Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus",
				"Anthropic-Ratelimit-Unified-Reset": reset,
			},
			checked: "claude-extra-usage-order-opus",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const opus = "claude-extra-usage-order-opus"
			manager, _, _ := newClaudeExtraUsageTestManager(t, opus, "block", nil)
			// The crossing headers arrive first, then a stale same-window response...
			crossing := claudeHeadersContext(t, tc.crossing)
			stale := claudeHeadersContext(t, tc.stale)
			// ...but the stale one is committed first.
			manager.MarkResult(stale, Result{AuthID: "cred-a", Provider: "claude", Model: opus, RouteModel: opus, Success: true})
			manager.MarkResult(crossing, Result{AuthID: "cred-a", Provider: "claude", Model: opus, RouteModel: opus, Success: true})
			auth, _ := manager.GetByID("cred-a")
			if manager.claudeExtraUsageRefusal(auth, tc.checked, tc.checked, time.Now()) == nil {
				t.Fatal("the crossing response was lost because its observer committed after a stale one")
			}
		})
	}
}

func TestClaudeExtraUsageAdoptedBlockBeatsAnAlreadyPickedCopy(t *testing.T) {
	for _, mode := range []string{"execute", "stream"} {
		t.Run(mode, func(t *testing.T) {
			model := "claude-extra-usage-adopt-picked-" + mode
			now := time.Now()
			manager, executor, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
			crossing := claudeHeadersContext(t, claudeExtraUsageSignals(now, nil))
			stale := claudeHeadersContext(t, map[string]string{
				"Anthropic-Ratelimit-Unified-Status": "allowed_warning", "Anthropic-Ratelimit-Unified-5h-Status": "allowed_warning",
				"Anthropic-Ratelimit-Unified-5h-Reset": strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10),
			})
			// The stale response commits first; the next request picks that snapshot.
			manager.MarkResult(stale, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
			opts := cliproxyexecutor.Options{
				RequestAfterAuthInterceptor: func(_ context.Context, req cliproxyexecutor.RequestAfterAuthInterceptRequest) cliproxyexecutor.RequestAfterAuthInterceptResponse {
					if authID, _ := req.Metadata[cliproxyexecutor.SelectedAuthMetadataKey].(string); authID == "cred-a" {
						// The crossing response, which arrived earlier, commits now.
						manager.MarkResult(crossing, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
					}
					return cliproxyexecutor.RequestAfterAuthInterceptResponse{}
				},
			}
			payload, errInvoke := invokeAfterAuthMode(manager, "claude", model, mode, opts)
			if calls := executor.Calls(); !reflect.DeepEqual(calls, []string{"cred-b"}) {
				t.Fatalf("executor calls = %v (payload %q, error %v), want the adopted block to move the request to cred-b", calls, payload, errInvoke)
			}
		})
	}
}

func TestClaudeExtraUsageAdoptedBlockSurvivesARefreshStartedEarlier(t *testing.T) {
	const model = "claude-extra-usage-adopt-refresh"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	crossing := claudeHeadersContext(t, claudeExtraUsageSignals(now, nil))
	stale := claudeHeadersContext(t, map[string]string{
		"Anthropic-Ratelimit-Unified-Status": "allowed_warning", "Anthropic-Ratelimit-Unified-5h-Status": "allowed_warning",
		"Anthropic-Ratelimit-Unified-5h-Reset": strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10),
	})
	manager.MarkResult(stale, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	// A token refresh starts from the stale snapshot...
	base, _ := manager.GetByID("cred-a")
	// ...then the earlier-arriving crossing response commits and is adopted...
	manager.MarkResult(crossing, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true})
	// ...and the refresh commits its copy afterwards.
	refreshed := base.Clone()
	if refreshed.Metadata == nil {
		refreshed.Metadata = map[string]any{}
	}
	refreshed.Metadata["access_token"] = "refreshed-token"
	if _, errUpd := manager.UpdateRefreshedAuth(WithSkipPersist(t.Context()), base, refreshed); errUpd != nil {
		t.Fatal(errUpd)
	}
	auth, _ := manager.GetByID("cred-a")
	if manager.claudeExtraUsageRefusal(auth, model, model, time.Now()) == nil {
		t.Fatalf("a refresh started before the adoption erased the block; signals = %v", auth.Quota.Signals)
	}
}
