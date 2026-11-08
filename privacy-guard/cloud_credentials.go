package main

import (
	"regexp"
	"strings"
)

var cloudCredentialLabelRE = regexp.MustCompile(`(?i)^\s*(?:\*\*)?(?:AccessKey[ _-]*ID|AccessKey[ _-]*Secret|Security[ _-]*Token|Secret[ _-]*ID|Secret[ _-]*Key)(?:\*\*)?\s*[:：]?\s*$`)
var cloudCredentialValueRE = regexp.MustCompile(`^\s*([A-Za-z0-9_+./=-]+)(?:\*\*复制\*\*|复制)?\s*$`)

// Console exports often place a credential label and its value on separate
// lines. Keep the original formatting and copy-button text outside the span.
func cloudCredentialSpans(text string) []textSpan {
	var spans []textSpan
	pending := false
	offset := 0
	for _, line := range strings.SplitAfter(text, "\n") {
		start := offset
		offset += len(line)
		if cloudCredentialLabelRE.MatchString(line) {
			pending = true
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if pending {
			if match := cloudCredentialValueRE.FindStringSubmatchIndex(line); match != nil {
				spans = append(spans, textSpan{start: start + match[2], end: start + match[3]})
			}
			pending = false
		}
	}
	return spans
}
