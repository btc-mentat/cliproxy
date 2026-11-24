package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestTargetedReauthentication(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			manager := coreauth.NewManager(nil, nil, nil)
			target := &coreauth.Auth{ID: "original.json", FileName: "original.json", Provider: provider, Metadata: map[string]any{"email": "User@example.test", "refresh_token": "fixture"}}
			scope := "organization_uuid"
			if provider == "codex" {
				scope = "account_id"
			} else {
				target.Metadata["account_uuid"] = "user"
			}
			target.Metadata[scope] = "original"
			if _, err := manager.Register(context.Background(), target); err != nil {
				t.Fatal(err)
			}
			h := &Handler{authManager: manager}
			record := &coreauth.Auth{ID: "new.json", FileName: "new.json", Provider: provider, Metadata: map[string]any{"email": "user@example.test", scope: "other", "account_uuid": "user"}}
			if err := h.bindReauthRecord(target.ID, record); err == nil {
				t.Fatal("accepted another workspace")
			}
			record.Metadata[scope] = "original"
			record.Metadata["email"] = "other@example.test"
			if err := h.bindReauthRecord(target.ID, record); err == nil {
				t.Fatal("accepted another account")
			}
			record.Metadata["email"] = "user@example.test"
			if err := h.bindReauthRecord("missing.json", record); err == nil {
				t.Fatal("accepted missing account")
			}
			if err := h.bindReauthRecord(target.ID, record); err != nil {
				t.Fatal(err)
			}
			if record.ID != target.ID || record.FileName != target.FileName {
				t.Fatal("did not retain original row")
			}
		})
	}
}

func TestReauthCallbackUpdatesOnlySelectedRow(t *testing.T) {
	oldService := newCodexOAuthService
	newCodexOAuthService = func(*config.Config) codexOAuthService { return &fakeCodexOAuthService{} }
	t.Cleanup(func() { newCodexOAuthService = oldService })
	dir := t.TempDir()
	// The fixture provider uses the code to choose the account it returns.
	name := "codex-codex-owner@example.test-free.json"
	metadata := map[string]any{"type": "codex", "email": "codex-owner@example.test", "refresh_token": "original", "priority": -1}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m := coreauth.NewManager(nil, nil, nil)
	if _, err = m.Register(context.Background(), &coreauth.Auth{ID: name, FileName: name, Provider: "codex", Metadata: metadata}); err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, m)
	router := gin.New()
	router.GET("/v8/management/oauth/auth-url", h.StartOAuthV8)
	for _, code := range []string{"someone-else", "owner"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v8/management/oauth/auth-url?provider=codex&reauth_id="+name, nil))
		var login struct{ State string }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &login) != nil || login.State == "" {
			t.Fatal("sign-in did not start", w.Code)
		}
		if _, err = WriteOAuthCallbackFileForPendingSession(dir, "codex", login.State, code, ""); err != nil {
			t.Fatal(err)
		}
		waitForOAuthSessionDone(t, login.State)
		_, message, _, _, done, ok := GetOAuthSessionDetails(login.State)
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if code != "owner" {
			if !ok || done || !strings.Contains(message, "different account") || string(saved) != string(data) {
				t.Fatal("wrong account was accepted or changed the selected file")
			}
		} else {
			var updated map[string]any
			if !done || json.Unmarshal(saved, &updated) != nil || updated["refresh_token"] != "refresh-owner" || updated["priority"] != float64(-1) {
				t.Fatal("expected refreshed credentials on the original reserve row")
			}
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("sign-in created another row", files)
	}
}
