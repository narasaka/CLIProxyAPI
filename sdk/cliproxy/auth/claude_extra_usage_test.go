package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
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
}
