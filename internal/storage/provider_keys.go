package storage

import (
	"os"
	"strings"
)

type ProviderConfig struct {
	Name       string `json:"name"`
	Label      string `json:"label"`
	EnvVar     string `json:"env_var"`
	Supports   string `json:"supports"`
	Configured bool   `json:"configured"`
	Source     string `json:"source"` // "ui", "env" ou "none"
	MaskedKey  string `json:"masked_key"`
}

func (s *SQLiteStore) ensureProviderTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS provider_settings (
			provider TEXT PRIMARY KEY,
			api_key TEXT NOT NULL
		);
	`)
	return err
}

func (s *SQLiteStore) SaveProviderKey(provider, apiKey string) error {
	if err := s.ensureProviderTable(); err != nil {
		return err
	}
	trimmed := strings.TrimSpace(apiKey)
	if trimmed == "" {
		_, err := s.db.Exec(`DELETE FROM provider_settings WHERE provider = ?`, provider)
		return err
	}
	_, err := s.db.Exec(`
		INSERT INTO provider_settings (provider, api_key)
		VALUES (?, ?)
		ON CONFLICT(provider) DO UPDATE SET api_key = excluded.api_key
	`, provider, trimmed)
	return err
}

func (s *SQLiteStore) LoadSavedProviderKeys() (map[string]string, error) {
	if err := s.ensureProviderTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT provider, api_key FROM provider_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var p, k string
		if err := rows.Scan(&p, &k); err == nil && strings.TrimSpace(k) != "" {
			out[p] = strings.TrimSpace(k)
		}
	}
	return out, rows.Err()
}

func maskAPIKey(k string) string {
	if k == "" {
		return ""
	}
	if len(k) <= 6 {
		return "****"
	}
	return k[:2] + strings.Repeat("*", len(k)-6) + k[len(k)-4:]
}

func (s *SQLiteStore) ListProviderConfigs() ([]ProviderConfig, error) {
	saved, err := s.LoadSavedProviderKeys()
	if err != nil {
		return nil, err
	}

	defs := []struct {
		name     string
		label    string
		envVar   string
		supports string
	}{
		{"abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP"},
		{"virustotal", "VirusTotal", "VT_API_KEY", "IP, Domínio, Hash"},
		{"alienvault_otx", "AlienVault OTX", "OTX_API_KEY", "IP, Domínio, Hash"},
		{"crowdsec_cti", "CrowdSec CTI", "CROWDSEC_CTI_API_KEY", "IP"},
	}

	res := make([]ProviderConfig, 0, len(defs))
	for _, d := range defs {
		cfg := ProviderConfig{
			Name:     d.name,
			Label:    d.label,
			EnvVar:   d.envVar,
			Supports: d.supports,
			Source:   "none",
		}
		if k, ok := saved[d.name]; ok && k != "" {
			cfg.Configured = true
			cfg.Source = "ui"
			cfg.MaskedKey = maskAPIKey(k)
		} else if envK := strings.TrimSpace(os.Getenv(d.envVar)); envK != "" {
			cfg.Configured = true
			cfg.Source = "env"
			cfg.MaskedKey = maskAPIKey(envK)
		}
		res = append(res, cfg)
	}
	return res, nil
}
