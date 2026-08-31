package auth

import (
    "encoding/hex"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
)

func TestGetKeyFromVault_Hex(t *testing.T) {
    // prepare a fake Vault response for KV v2
    hexVal := hex.EncodeToString([]byte("supersecret"))
    respObj := map[string]any{"data": map[string]any{"data": map[string]any{"key": hexVal}}}
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // check token header present but don't echo it
        if r.Header.Get("X-Vault-Token") == "" {
            http.Error(w, "missing token", http.StatusUnauthorized)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(respObj)
    }))
    defer srv.Close()

    os.Setenv("VAULT_ADDR", srv.URL)
    os.Setenv("VAULT_TOKEN", "testtoken")
    defer os.Unsetenv("VAULT_ADDR")
    defer os.Unsetenv("VAULT_TOKEN")

    b, err := GetKeyFromVault("secret/data/test")
    if err != nil {
        t.Fatalf("GetKeyFromVault failed: %v", err)
    }
    if string(b) != "supersecret" {
        t.Fatalf("unexpected key, got %q", string(b))
    }
}

func TestWriteSecretFieldToVault_OK(t *testing.T) {
    // echo back OK
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            http.Error(w, "bad method", http.StatusMethodNotAllowed)
            return
        }
        if r.Header.Get("X-Vault-Token") == "" {
            http.Error(w, "missing token", http.StatusUnauthorized)
            return
        }
        w.WriteHeader(204)
    }))
    defer srv.Close()

    os.Setenv("VAULT_ADDR", srv.URL)
    os.Setenv("VAULT_TOKEN", "tkn")
    defer os.Unsetenv("VAULT_ADDR")
    defer os.Unsetenv("VAULT_TOKEN")

    if err := WriteSecretFieldToVault("secret/data/test", "k", []byte("abc")); err != nil {
        t.Fatalf("WriteSecretFieldToVault failed: %v", err)
    }
}
