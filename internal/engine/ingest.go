package engine

import (
	"encoding/json"
	"net"
	"net/mail"
	"regexp"
	"strings"

	"argos/internal/domain"
)

var (
	md5Regex    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1Regex   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
	tokenRegex  = regexp.MustCompile(`[^\s,;]+`)
)

func RefangIndicator(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "hxxps://", "https://")
	s = strings.ReplaceAll(s, "hxxp://", "http://")
	s = strings.ReplaceAll(s, "HXXPS://", "https://")
	s = strings.ReplaceAll(s, "HXXP://", "http://")
	s = strings.ReplaceAll(s, "[.]", ".")
	s = strings.ReplaceAll(s, "(.)", ".")
	s = strings.ReplaceAll(s, "[:]", ":")
	s = strings.ReplaceAll(s, "[@]", "@")
	s = strings.Trim(s, `"'<>[]()`)
	return strings.TrimSpace(s)
}

func ClassifyArtifact(raw string) (normalized string, artType domain.ArtifactType, ok bool) {
	clean := RefangIndicator(raw)
	if clean == "" {
		return "", "", false
	}

	if strings.HasPrefix(strings.ToLower(clean), "http://") || strings.HasPrefix(strings.ToLower(clean), "https://") {
		return clean, domain.TypeURL, true
	}

	if ip := net.ParseIP(clean); ip != nil {
		return ip.String(), domain.TypeIP, true
	}

	lower := strings.ToLower(clean)
	if md5Regex.MatchString(lower) || sha1Regex.MatchString(lower) || sha256Regex.MatchString(lower) {
		return lower, domain.TypeHash, true
	}

	if _, err := mail.ParseAddress(clean); err == nil && strings.Contains(clean, "@") {
		return lower, domain.TypeEmail, true
	}

	if domainRegex.MatchString(lower) {
		return lower, domain.TypeDomain, true
	}

	return "", "", false
}

func ExtractArtifactsFromText(text string) []string {
	var found []string
	seen := make(map[string]bool)

	addCandidate := func(cand string) {
		norm, _, ok := ClassifyArtifact(cand)
		if !ok {
			return
		}
		if !seen[norm] {
			seen[norm] = true
			found = append(found, norm)
		}
	}

	for _, tok := range tokenRegex.FindAllString(text, -1) {
		addCandidate(tok)
		if idx := strings.Index(tok, "="); idx != -1 && idx+1 < len(tok) {
			addCandidate(tok[idx+1:])
		}
	}
	return found
}

func ExtractArtifactsFromJSONBytes(data []byte) ([]string, error) {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var out []string

	var walk func(v any)
	walk = func(v any) {
		switch val := v.(type) {
		case string:
			for _, item := range ExtractArtifactsFromText(val) {
				if !seen[item] {
					seen[item] = true
					out = append(out, item)
				}
			}
		case []any:
			for _, elem := range val {
				walk(elem)
			}
		case map[string]any:
			for _, elem := range val {
				walk(elem)
			}
		}
	}

	walk(payload)
	return out, nil
}
