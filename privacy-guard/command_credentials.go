package main

import (
	stdpath "path"
	"strings"
)

// Keep byte ranges so shell quoting and escapes survive a mask/restore round trip.
// A command separator ends credential-option recognition.
func commandCredentialSpans(text string) []textSpan {
	var spans []textSpan
	mode, wantValue := "", false
	pendingLogin := false
	for i := 0; i < len(text); {
		if strings.ContainsRune(";|&\n\r", rune(text[i])) {
			mode = ""
			wantValue = false
			pendingLogin = false
			i++
			continue
		}
		if text[i] == ' ' || text[i] == '\t' {
			i++
			continue
		}
		start := i
		quote := byte(0)
		for i < len(text) {
			c := text[i]
			if c == '\\' && quote != '\'' && i+1 < len(text) {
				i += 2
				continue
			}
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				i++
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				i++
				continue
			}
			if strings.ContainsRune(" \t\r\n;|&", rune(c)) {
				break
			}
			i++
		}
		word := text[start:i]
		if word == "\\\n" {
			continue
		}
		if !wantValue && mode == "" {
			switch stdpath.Base(trimQuotes(word)) {
			case "docker", "modctl", "clawhub":
				pendingLogin = true
				mode = ""
				continue
			case "mysql", "mysqldump", "mariadb":
				mode = "mysql"
				wantValue = false
				continue
			}
		}
		if !wantValue && pendingLogin && word == "login" {
			mode = "login"
			pendingLogin = false
			continue
		}
		if mode == "" {
			continue
		}
		valueStart := start
		switch {
		case wantValue:
			wantValue = false
		case word == "--":
			mode = ""
			continue
		case word == "-u" || word == "--user" || mode == "login" && (word == "--username" || word == "--password" || word == "--token" || word == "-p"):
			wantValue = true
			continue
		case mode == "login" && strings.HasPrefix(word, "--username="):
			valueStart += len("--username=")
		case mode == "login" && strings.HasPrefix(word, "--token="):
			valueStart += len("--token=")
		case strings.HasPrefix(word, "--user="):
			valueStart += len("--user=")
		case strings.HasPrefix(word, "--password="):
			valueStart += len("--password=")
		case strings.HasPrefix(word, "-u") && !strings.HasPrefix(word, "--"):
			valueStart += 2
		case strings.HasPrefix(word, "-p") && !strings.HasPrefix(word, "--"):
			valueStart += 2
		default:
			continue
		}
		if valueStart >= i {
			continue
		} // bare -p prompts interactively
		raw := text[valueStart:i]
		value := trimQuotes(raw)
		if isExactReference(value) || isMaskToken(value) {
			continue
		}
		if value != raw {
			valueStart += strings.Index(raw, value)
		}
		spans = append(spans, textSpan{start: valueStart, end: valueStart + len(value)})
	}
	return spans
}
