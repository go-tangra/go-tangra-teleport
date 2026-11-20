// Package openapi embeds the Teleport module's browser API contract.
package openapi

import _ "embed"

// Teleport is the OpenAPI 3.1 document served and validated by the service.
//
//go:embed teleport.yaml
var Teleport []byte
