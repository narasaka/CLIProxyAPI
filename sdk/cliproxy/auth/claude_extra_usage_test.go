package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
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
		name       string
		overrides  map[string]string
		sharedOnly bool
		want       time.Duration
		blocked    bool
	}{
		{name: "plan limit used up with overage allowed", sharedOnly: true, want: 2 * time.Hour, blocked: true},
		{name: "overage allowed_warning", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Overage-Status": "allowed_warning"}, sharedOnly: true, want: 2 * time.Hour, blocked: true},
		{name: "overage rejected is a real upstream 429", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Overage-Status": "rejected"}, sharedOnly: true},
		{name: "overage status missing", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Overage-Status": ""}, sharedOnly: true},
		{name: "plan limit not used up", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed_warning", "Anthropic-Ratelimit-Unified-5h-Status": "allowed_warning"}, sharedOnly: true},
		{name: "reset already passed", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Reset": at(-time.Minute), "Anthropic-Ratelimit-Unified-5h-Reset": at(-time.Minute)}, sharedOnly: true},
		{name: "no reset", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Reset": "", "Anthropic-Ratelimit-Unified-5h-Reset": ""}, sharedOnly: true},
		{name: "reset beyond any plan window", overrides: map[string]string{"Anthropic-Ratelimit-Unified-Reset": at(9 * 24 * time.Hour), "Anthropic-Ratelimit-Unified-5h-Reset": ""}, sharedOnly: true},
		{name: "latest rejected window reset wins", overrides: map[string]string{"Anthropic-Ratelimit-Unified-7d-Status": "rejected", "Anthropic-Ratelimit-Unified-7d-Reset": at(30 * time.Hour)}, sharedOnly: true, want: 30 * time.Hour, blocked: true},
		{name: "allowed window reset is ignored", overrides: map[string]string{"Anthropic-Ratelimit-Unified-7d-Status": "allowed", "Anthropic-Ratelimit-Unified-7d-Reset": at(30 * time.Hour)}, sharedOnly: true, want: 2 * time.Hour, blocked: true},
		{
			name:       "per-model weekly claim does not block the whole credential",
			overrides:  map[string]string{"Anthropic-Ratelimit-Unified-Representative-Claim": "seven_day_opus", "Anthropic-Ratelimit-Unified-5h-Status": "allowed"},
			sharedOnly: true,
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
			sharedOnly: true,
			want:       time.Hour,
			blocked:    true,
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
			sharedOnly: true,
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
			resetAt, blocked := claudeExtraUsageResetAt(claudeExtraUsageSignals(now, tt.overrides), tt.sharedOnly, now)
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
	if errRefuse := manager.claudeExtraUsageRefusal(auth, "claude-opus-test", now); !isCredentialTerminatedError(errRefuse) {
		t.Fatalf("opus refusal = %v, want credential refusal", errRefuse)
	}
	if errRefuse := manager.claudeExtraUsageRefusal(auth, "claude-sonnet-test", now); errRefuse != nil {
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
	if !errors.As(manager.claudeExtraUsageRefusal(auth, "claude-opus-test", now), &refusal) || (refusal.recoverAt.Sub(now)-6*24*time.Hour).Abs() > time.Second {
		t.Fatalf("opus refusal = %+v, want recovery in 6 days", refusal)
	}
	if !errors.As(manager.claudeExtraUsageRefusal(auth, "claude-sonnet-test", now), &refusal) || (refusal.recoverAt.Sub(now)-time.Hour).Abs() > time.Second {
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

func TestClaudeExtraUsageStaleStreamCompletionKeepsBlock(t *testing.T) {
	const model = "claude-extra-usage-stale-stream"
	now := time.Now()
	manager, _, _ := newClaudeExtraUsageTestManager(t, model, "block", nil)
	markWithHeaders := func(executionSeq uint64, signals map[string]string) {
		ctx := internallogging.WithResponseHeadersHolder(WithSkipPersist(t.Context()))
		headers := http.Header{}
		for key, value := range signals {
			headers.Set(key, value)
		}
		internallogging.SetResponseHeaders(ctx, headers)
		manager.MarkResult(ctx, Result{AuthID: "cred-a", Provider: "claude", Model: model, RouteModel: model, Success: true, ExecutionSeq: executionSeq})
	}
	refused := func() bool {
		auth, _ := manager.GetByID("cred-a")
		return manager.claudeExtraUsageRefusal(auth, model, time.Now()) != nil
	}
	allowed := map[string]string{
		"Anthropic-Ratelimit-Unified-Status":    "allowed",
		"Anthropic-Ratelimit-Unified-5h-Status": "allowed",
		"Anthropic-Ratelimit-Unified-Reset":     strconv.FormatInt(now.Add(2*time.Hour).Unix(), 10),
	}

	// Request 2 crosses the plan limit and is recorded first.
	markWithHeaders(2, claudeExtraUsageSignals(now, nil))
	if !refused() {
		t.Fatal("not refused after the response that crossed the limit")
	}
	// Stream 1, dispatched before the limit was crossed, ends later with its old headers.
	markWithHeaders(1, allowed)
	if !refused() {
		t.Fatal("a stale stream completion lifted the block")
	}
	// A response dispatched after the block still replaces the snapshot.
	markWithHeaders(3, allowed)
	if refused() {
		t.Fatal("a newer allowed response did not lift the block")
	}
}
