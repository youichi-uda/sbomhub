package assets

import "embed"

// Fonts contains embedded font files for PDF generation
//
//go:embed fonts/*.ttf
var Fonts embed.FS
