package model

// SPDX3Document represents the root structure of an SPDX 3.0 document
type SPDX3Document struct {
	Context string         `json:"@context"`
	Graph   []SPDX3Element `json:"@graph"`
}

// SPDX3Element represents an element in the SPDX 3.0 @graph array
type SPDX3Element struct {
	SpdxID             string            `json:"spdxId"`
	Type               string            `json:"type"`
	Name               string            `json:"name,omitempty"`
	PackageVersion     string            `json:"packageVersion,omitempty"`
	ExternalIdentifier []SPDX3ExternalID `json:"externalIdentifier,omitempty"`
	// Additional fields for packages
	DownloadLocation string `json:"downloadLocation,omitempty"`
	PackageUrl       string `json:"packageUrl,omitempty"`
	// License information
	DeclaredLicense string `json:"declaredLicense,omitempty"`
}

// SPDX3ExternalID represents an external identifier in SPDX 3.0
type SPDX3ExternalID struct {
	ExternalIDType string `json:"externalIdentifierType"`
	Identifier     string `json:"identifier"`
}
