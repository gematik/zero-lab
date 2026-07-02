package proxy

import (
	"encoding/base64"
	"html/template"

	qrcode "github.com/skip2/go-qrcode"
)

// qrImage renders content (the OIDF authorization URL) as a base64 PNG data URI for an <img src>, so the
// decoupled flow can be completed by scanning with a second device.
func qrImage(content string) (template.URL, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}
