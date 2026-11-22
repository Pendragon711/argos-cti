package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"argos/internal/domain"
)

type Provider interface {
	Name() string
	Supports(t domain.ArtifactType) bool
	Enrich(ctx context.Context, value string, t domain.ArtifactType) (domain.EnrichmentResult, error)
}

type AbuseIPDB struct {
	APIKey string
	Client *http.Client
}

func NewAbuseIPDBFromEnv() *AbuseIPDB {
	return &AbuseIPDB{
		APIKey: os.Getenv("ABUSEIPDB_API_KEY"),
		Client: &http.Client{Timeout: 7 * time.Second},
	}
}

func (a *AbuseIPDB) Name() string                        { return "abuseipdb" }
func (a *AbuseIPDB) Supports(t domain.ArtifactType) bool { return t == domain.TypeIP && a.APIKey != "" }

func (a *AbuseIPDB) Enrich(ctx context.Context, value string, _ domain.ArtifactType) (domain.EnrichmentResult, error) {
	endpoint := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", url.QueryEscape(value))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	req.Header.Set("Key", a.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.Client.Do(req)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	defer resp.Body.Close()

	var body struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			ISP                  string `json:"isp"`
			TotalReports         int    `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.EnrichmentResult{}, err
	}

	return domain.EnrichmentResult{
		Provider:  a.Name(),
		Malicious: body.Data.AbuseConfidenceScore >= 75,
		Score:     body.Data.AbuseConfidenceScore,
		Tags:      []string{body.Data.CountryCode, body.Data.ISP},
		Raw: map[string]any{
			"total_reports": body.Data.TotalReports,
			"isp":           body.Data.ISP,
		},
	}, nil
}

type VirusTotal struct {
	APIKey string
	Client *http.Client
}

func NewVirusTotalFromEnv() *VirusTotal {
	return &VirusTotal{
		APIKey: os.Getenv("VT_API_KEY"),
		Client: &http.Client{Timeout: 7 * time.Second},
	}
}

func (v *VirusTotal) Name() string { return "virustotal" }
func (v *VirusTotal) Supports(t domain.ArtifactType) bool {
	return v.APIKey != "" && (t == domain.TypeIP || t == domain.TypeDomain || t == domain.TypeHash)
}

func (v *VirusTotal) Enrich(ctx context.Context, value string, t domain.ArtifactType) (domain.EnrichmentResult, error) {
	var path string
	switch t {
	case domain.TypeIP:
		path = "/api/v3/ip_addresses/" + value
	case domain.TypeDomain:
		path = "/api/v3/domains/" + value
	case domain.TypeHash:
		path = "/api/v3/files/" + value
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com"+path, nil)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	req.Header.Set("x-apikey", v.APIKey)

	resp, err := v.Client.Do(req)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	defer resp.Body.Close()

	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				Tags []string `json:"tags"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.EnrichmentResult{}, err
	}

	mal := body.Data.Attributes.LastAnalysisStats.Malicious
	sus := body.Data.Attributes.LastAnalysisStats.Suspicious
	score := mal * 10
	if score > 100 {
		score = 100
	}

	return domain.EnrichmentResult{
		Provider:  v.Name(),
		Malicious: mal > 0,
		Score:     score,
		Tags:      body.Data.Attributes.Tags,
		Raw: map[string]any{
			"malicious":  mal,
			"suspicious": sus,
		},
	}, nil
}

type AlienVaultOTX struct {
	APIKey string
	Client *http.Client
}

func NewAlienVaultOTXFromEnv() *AlienVaultOTX {
	return &AlienVaultOTX{
		APIKey: os.Getenv("OTX_API_KEY"),
		Client: &http.Client{Timeout: 7 * time.Second},
	}
}

func (o *AlienVaultOTX) Name() string { return "alienvault_otx" }
func (o *AlienVaultOTX) Supports(t domain.ArtifactType) bool {
	return t == domain.TypeIP || t == domain.TypeDomain || t == domain.TypeHash
}

func (o *AlienVaultOTX) Enrich(ctx context.Context, value string, t domain.ArtifactType) (domain.EnrichmentResult, error) {
	var section string
	switch t {
	case domain.TypeIP:
		section = "IPv4/" + value + "/general"
	case domain.TypeDomain:
		section = "domain/" + value + "/general"
	case domain.TypeHash:
		section = "file/" + value + "/general"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://otx.alienvault.com/api/v1/indicators/"+section, nil)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	if o.APIKey != "" {
		req.Header.Set("X-OTX-API-KEY", o.APIKey)
	}

	resp, err := o.Client.Do(req)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	defer resp.Body.Close()

	var body struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.EnrichmentResult{}, err
	}

	count := body.PulseInfo.Count
	score := count * 15
	if score > 100 {
		score = 100
	}

	return domain.EnrichmentResult{
		Provider:  o.Name(),
		Malicious: count >= 3,
		Score:     score,
		Tags:      []string{fmt.Sprintf("pulses:%d", count)},
		Raw: map[string]any{
			"pulse_count": count,
		},
	}, nil
}

type CrowdSecCTI struct {
	APIKey string
	Client *http.Client
}

func NewCrowdSecCTIFromEnv() *CrowdSecCTI {
	return &CrowdSecCTI{
		APIKey: os.Getenv("CROWDSEC_CTI_API_KEY"),
		Client: &http.Client{Timeout: 7 * time.Second},
	}
}

func (c *CrowdSecCTI) Name() string                        { return "crowdsec_cti" }
func (c *CrowdSecCTI) Supports(t domain.ArtifactType) bool { return t == domain.TypeIP && c.APIKey != "" }

func (c *CrowdSecCTI) Enrich(ctx context.Context, value string, _ domain.ArtifactType) (domain.EnrichmentResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cti.api.crowdsec.net/v2/smoke/"+value, nil)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	req.Header.Set("x-api-key", c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		return domain.EnrichmentResult{}, err
	}
	defer resp.Body.Close()

	var body struct {
		Behaviors []string `json:"behaviors"`
		Score     int      `json:"score"`
		Attack    bool     `json:"attack_details_present"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.EnrichmentResult{}, err
	}

	score := body.Score * 20
	if score > 100 {
		score = 100
	}

	return domain.EnrichmentResult{
		Provider:  c.Name(),
		Malicious: score >= 60 || body.Attack,
		Score:     score,
		Tags:      body.Behaviors,
	}, nil
}
