package model

import (
	"time"

	"github.com/google/uuid"
)

// LicensePolicyType represents the policy type for a license
type LicensePolicyType string

const (
	LicensePolicyAllowed LicensePolicyType = "allowed"
	LicensePolicyDenied  LicensePolicyType = "denied"
	LicensePolicyReview  LicensePolicyType = "review"
)

// LicensePolicy represents a license policy rule
type LicensePolicy struct {
	ID          uuid.UUID         `json:"id" db:"id"`
	ProjectID   uuid.UUID         `json:"project_id" db:"project_id"`
	LicenseID   string            `json:"license_id" db:"license_id"` // SPDX license identifier
	LicenseName string            `json:"license_name" db:"license_name"`
	PolicyType  LicensePolicyType `json:"policy_type" db:"policy_type"`
	Reason      string            `json:"reason,omitempty" db:"reason"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

// LicenseViolation represents a component that violates a license policy
type LicenseViolation struct {
	ComponentID   uuid.UUID         `json:"component_id"`
	ComponentName string            `json:"component_name"`
	Version       string            `json:"version"`
	License       string            `json:"license"`
	PolicyType    LicensePolicyType `json:"policy_type"`
	Reason        string            `json:"reason,omitempty"`
}

// CommonLicenses contains well-known SPDX license identifiers
var CommonLicenses = map[string]string{
	"MIT":              "MIT License",
	"Apache-2.0":       "Apache License 2.0",
	"GPL-2.0-only":     "GNU General Public License v2.0 only",
	"GPL-2.0-or-later": "GNU General Public License v2.0 or later",
	"GPL-3.0-only":     "GNU General Public License v3.0 only",
	"GPL-3.0-or-later": "GNU General Public License v3.0 or later",
	"LGPL-2.1-only":    "GNU Lesser General Public License v2.1 only",
	"LGPL-2.1-or-later": "GNU Lesser General Public License v2.1 or later",
	"LGPL-3.0-only":    "GNU Lesser General Public License v3.0 only",
	"LGPL-3.0-or-later": "GNU Lesser General Public License v3.0 or later",
	"BSD-2-Clause":     "BSD 2-Clause \"Simplified\" License",
	"BSD-3-Clause":     "BSD 3-Clause \"New\" or \"Revised\" License",
	"ISC":              "ISC License",
	"MPL-2.0":          "Mozilla Public License 2.0",
	"CC0-1.0":          "Creative Commons Zero v1.0 Universal",
	"Unlicense":        "The Unlicense",
	"AGPL-3.0-only":    "GNU Affero General Public License v3.0 only",
	"AGPL-3.0-or-later": "GNU Affero General Public License v3.0 or later",
	"EPL-1.0":          "Eclipse Public License 1.0",
	"EPL-2.0":          "Eclipse Public License 2.0",
	"CDDL-1.0":         "Common Development and Distribution License 1.0",
	"WTFPL":            "Do What The F*ck You Want To Public License",
	"Zlib":             "zlib License",
	"0BSD":             "BSD Zero Clause License",
}
