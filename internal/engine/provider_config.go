package engine

import (
	"os"
	"strings"

	"argos/internal/providers"
)

func (o *Orchestrator) ApplyProviderKeys(saved map[string]string) {
	resolve := func(name, envVar string) string {
		if k, ok := saved[name]; ok && strings.TrimSpace(k) != "" {
			return strings.TrimSpace(k)
		}
		return strings.TrimSpace(os.Getenv(envVar))
	}

	for _, p := range o.providers {
		switch v := p.(type) {
		case *providers.AbuseIPDB:
			v.APIKey = resolve("abuseipdb", "ABUSEIPDB_API_KEY")
		case *providers.VirusTotal:
			v.APIKey = resolve("virustotal", "VT_API_KEY")
		case *providers.AlienVaultOTX:
			v.APIKey = resolve("alienvault_otx", "OTX_API_KEY")
		case *providers.CrowdSecCTI:
			v.APIKey = resolve("crowdsec_cti", "CROWDSEC_CTI_API_KEY")
		}
	}
}
