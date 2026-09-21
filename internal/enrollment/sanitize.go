package enrollment

import "strings"

// maxMessageLines bounds a submitted message to a handful of lines
// (endpoint-review.md F3: "bound line count") -- enough for a genuine
// short note, not enough to grow into a screen-filling wall of
// fabricated "fields" an approver might mistake for service-generated
// content.
const maxMessageLines = 5

// sanitizeFreeText strips characters that let an anonymous, unverified
// string manipulate how an approver reads it (endpoint-review.md F3):
// C0 control characters other than a plain newline (dropped once
// maxNewlines is reached) or tab, and the Unicode bidirectional
// embedding/override/isolate characters, which can visually reorder
// surrounding text to disguise what the string actually says. This is
// display-safety hardening, not a substitute for treating the result as
// untrusted, unverified content everywhere it's later shown.
func sanitizeFreeText(s string, maxNewlines int) string {
	var b strings.Builder
	b.Grow(len(s))
	newlines := 0
	for _, r := range s {
		switch {
		case r == '\n':
			if newlines >= maxNewlines {
				continue
			}
			newlines++
			b.WriteRune(r)
		case r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// Other C0 controls and DEL: drop.
		case isBidiControl(r):
			// Drop: these can reorder how surrounding text renders
			// without changing its underlying bytes.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isBidiControl reports whether r is one of the Unicode bidirectional
// formatting characters: the legacy marks/embeddings/overrides (LRM,
// RLM, LRE, RLE, PDF, LRO, RLO) and the newer isolates (LRI, RLI, FSI,
// PDI).
func isBidiControl(r rune) bool {
	switch r {
	case 0x200E, 0x200F,
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069:
		return true
	default:
		return false
	}
}
