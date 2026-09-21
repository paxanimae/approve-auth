// Package qrcode renders a QR code as a self-contained inline SVG.
package qrcode

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// SVG renders content as a QR code, returned as a self-contained
// <svg> element with no external resources -- safe to embed directly
// in an HTML response via template.HTML. size is the rendered CSS
// width/height in pixels; the actual module count is whatever the
// encoding needs, scaled to fit via the viewBox.
//
// qr.H (~30% error correction) is used deliberately, not the smaller
// default: this is meant to be scanned off a physical screen -- a
// reception TV, a warehouse display -- at an angle, from a few feet
// away, possibly through screen glare, not from a printed page held
// close. The extra redundancy costs more modules, but the encoded
// content here (a short admin-console URL) is nowhere near the format's
// capacity even at the highest correction level, so there's no reason
// to trade scan reliability for a marginally smaller code.
func SVG(content string, size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("qrcode: size must be positive, got %d", size)
	}
	code, err := qr.Encode(content, qr.H)
	if err != nil {
		return "", fmt.Errorf("qrcode: encoding: %w", err)
	}

	modules := code.Size
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="QR code">`, modules, modules, size, size)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/>`)
	for y := 0; y < modules; y++ {
		for x := 0; x < modules; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="1" height="1" fill="#000"/>`, x, y)
			}
		}
	}
	b.WriteString(`</svg>`)
	return b.String(), nil
}
