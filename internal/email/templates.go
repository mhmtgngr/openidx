package email

import "embed"

//go:embed templates/*.html
var templateFS embed.FS
