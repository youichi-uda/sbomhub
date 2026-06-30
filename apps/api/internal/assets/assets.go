package assets

import "embed"

// Fonts contains embedded font files for PDF generation.
//
// M11 Phase D F169 — third-party font license provenance:
//   - IPAGothic.ttf is sub-licensed under the IPA Font License Agreement
//     v1.0. See fonts/LICENSE-IPAGothic.txt for the verbatim license text
//     and SBOMHub redistribution compliance summary. The license file is
//     embedded alongside the binary so re-distributors of SBOMHub
//     (including AGPL forks) automatically carry the upstream license
//     with the font.
//   - SHA256 of the redistributed font is documented in the LICENSE file.
//   - IPA Font License is compatible with AGPL-3.0 re-distribution as
//     long as the file is not renamed or modified (we ship it byte-for-
//     byte from upstream).
//
//go:embed fonts/*.ttf fonts/LICENSE-*.txt
var Fonts embed.FS
