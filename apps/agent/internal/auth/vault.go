package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// GetKeyFromVault attempts to read a secret value from HashiCorp Vault KV v2.
// It requires VAULT_ADDR and VAULT_TOKEN to be set in the environment.
// secretPath is the path like "secret/data/siem/buffer". The function will
// look for common fields and return the decoded bytes if the secret is hex encoded,
// otherwise returns raw bytes of the value string.
func GetKeyFromVault(secretPath string) ([]byte, error) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil, errors.New("VAULT_ADDR or VAULT_TOKEN not set")
	}
	// build URL
	url := strings.TrimRight(addr, "/") + "/v1/" + strings.TrimLeft(secretPath, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// KV v2 stores data under data.data
	var val any
	if data, ok := out["data"].(map[string]any); ok {
		if dd, ok2 := data["data"].(map[string]any); ok2 {
			// pick first value
			for _, v := range dd {
				val = v
				break
			}
		} else {
			// sometimes data is directly the map
			for _, v := range data {
				val = v
				break
			}
		}
	}
	if val == nil {
		return nil, errors.New("no secret value found in vault response")
	}
	s := fmt.Sprintf("%v", val)
	// try hex decode
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return []byte(s), nil
}

// WriteKeyToVault writes a hex-encoded key to Vault KV v2 at the given secretPath.
// Requires VAULT_ADDR and VAULT_TOKEN environment variables.
func WriteKeyToVault(secretPath string, key []byte) error {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return errors.New("VAULT_ADDR or VAULT_TOKEN not set")
	}
	hexKey := hex.EncodeToString(key)
	payload := map[string]any{"data": map[string]any{"key": hexKey}}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := strings.TrimRight(addr, "/") + "/v1/" + strings.TrimLeft(secretPath, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vault write request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("vault write status: %d", resp.StatusCode)
	}
	return nil
}
