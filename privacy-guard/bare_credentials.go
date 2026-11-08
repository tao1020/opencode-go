package main

import (
	"math"
	"strings"
)

// Bare values are considered only in message text, never in tool names,
// schemas or protocol identities. Explicit credential fields use their own rules.
func bareCredentialText(p path) bool {
	return len(p) == 3 && p[0] == "messages" && p[1] == "[]" && p[2] == "content" ||
		len(p) == 5 && p[0] == "messages" && p[1] == "[]" && p[2] == "content" && p[3] == "[]" && p[4] == "text"
}

func looksLikeBareCredential(value string) bool {
	if len(value) < 20 || len(value) > 128 || isMaskToken(value) {
		return false
	}
	var counts [128]int
	lower, upper, digits, earlyDigits := 0, 0, 0, 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= '0' && c <= '9':
			digits++
			if i < len(value)-4 {
				earlyDigits++
			}
		case c == '_':
		default:
			return false
		}
		counts[c]++
	}
	if lower < 2 || upper < 2 || digits < 2 || earlyDigits == 0 {
		return false
	}
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(len(value))
			entropy -= p * math.Log2(p)
		}
	}
	return entropy >= 3.5
}

func bareCredentials(text string) []string {
	var found []string
	for _, line := range strings.Split(text, "\n") {
		value := strings.TrimSpace(line)
		if looksLikeBareCredential(value) {
			found = append(found, value)
		}
	}
	return found
}
