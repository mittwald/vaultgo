package vault

import "strings"

func resolvePath(parts []string) string {
	trimmedParts := make([]string, len(parts))
	for i, v := range parts {
		trimmedParts[i] = strings.Trim(v, "/")
	}
	return strings.Join(trimmedParts, "/")
}
