package api

import (
	"fmt"
	"strings"
)

// DotEnvEntry represents a single parsed key-value pair from a .env file.
type DotEnvEntry struct {
	Key   string
	Value string
}

// ParseDotEnv parses .env text into key-value pairs, supporting comments,
// blank lines, optional "export " prefixes, and single/double-quoted values.
func ParseDotEnv(raw string) ([]DotEnvEntry, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	entries := make([]DotEnvEntry, 0, len(lines))

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "export ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
		}

		eqIdx := strings.IndexByte(trimmed, '=')
		if eqIdx <= 0 {
			return nil, fmt.Errorf("invalid .env syntax at line %d", i+1)
		}

		key := strings.TrimSpace(trimmed[:eqIdx])
		if key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("invalid .env key %q at line %d", key, i+1)
		}

		valRaw := strings.TrimSpace(trimmed[eqIdx+1:])
		val := parseDotEnvValue(valRaw)
		entries = append(entries, DotEnvEntry{Key: key, Value: val})
	}

	return entries, nil
}

func parseDotEnvValue(raw string) string {
	if len(raw) >= 2 {
		if raw[0] == '"' && raw[len(raw)-1] == '"' {
			inner := raw[1 : len(raw)-1]
			replacer := strings.NewReplacer(
				`\\`, `\`,
				`\"`, `"`,
				`\n`, "\n",
				`\r`, "\r",
				`\t`, "\t",
			)
			return replacer.Replace(inner)
		}
		if raw[0] == '\'' && raw[len(raw)-1] == '\'' {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

// FormatDotEnv serializes key-value pairs into standard .env text format.
func FormatDotEnv(entries []DotEnvEntry) string {
	var b strings.Builder
	for _, entry := range entries {
		b.WriteString(entry.Key)
		b.WriteByte('=')
		b.WriteString(formatDotEnvValue(entry.Value))
		b.WriteByte('\n')
	}
	return b.String()
}

func formatDotEnvValue(val string) string {
	if val == "" {
		return ""
	}
	needsQuotes := strings.ContainsAny(val, " \t\n\r\"'#")
	if !needsQuotes {
		return val
	}
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"\t", `\t`,
	)
	return `"` + replacer.Replace(val) + `"`
}
