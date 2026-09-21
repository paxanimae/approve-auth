package qrcode_test

import (
	"strings"
	"testing"

	"github.com/paxanimae/approve-auth/internal/qrcode"
)

func TestSVG_ProducesWellFormedSVG(t *testing.T) {
	svg, err := qrcode.SVG("https://admin.example.test/?open_request=abc-123", 240)
	if err != nil {
		t.Fatalf("SVG: %v", err)
	}
	if !strings.HasPrefix(svg, "<svg ") {
		t.Errorf("output does not start with an <svg> tag: %.60s", svg)
	}
	if !strings.HasSuffix(svg, "</svg>") {
		t.Errorf("output does not end with </svg>: %.60s", svg)
	}
	if !strings.Contains(svg, `width="240" height="240"`) {
		t.Errorf("output does not honor the requested size: %.200s", svg)
	}
	if !strings.Contains(svg, `fill="#000"`) {
		t.Error("output has no black modules at all -- content did not encode")
	}
}

func TestSVG_DifferentContentProducesDifferentOutput(t *testing.T) {
	a, err := qrcode.SVG("https://admin.example.test/?open_request=aaaa", 200)
	if err != nil {
		t.Fatalf("SVG (a): %v", err)
	}
	b, err := qrcode.SVG("https://admin.example.test/?open_request=bbbb", 200)
	if err != nil {
		t.Fatalf("SVG (b): %v", err)
	}
	if a == b {
		t.Error("two different contents produced identical SVG output")
	}
}

func TestSVG_RejectsNonPositiveSize(t *testing.T) {
	if _, err := qrcode.SVG("https://admin.example.test/", 0); err == nil {
		t.Error("SVG with size=0: got nil error, want one")
	}
	if _, err := qrcode.SVG("https://admin.example.test/", -10); err == nil {
		t.Error("SVG with a negative size: got nil error, want one")
	}
}

func TestSVG_ErrorsOnContentExceedingCapacity(t *testing.T) {
	// qr.H's highest version still has a finite byte capacity -- an
	// absurdly long string must surface as an error, not a panic.
	huge := strings.Repeat("x", 10_000)
	if _, err := qrcode.SVG(huge, 100); err == nil {
		t.Error("SVG with oversized content: got nil error, want one")
	}
}
