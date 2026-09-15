// Package aws holds AWS provider-level wiring: it registers AWS-specific data
// (such as remediation templates) into the provider-neutral engines.
//
// This package is imported for its side effects (init registration). Import it
// with a blank_identifier from the command layer:
//
// import _ "sift/audit/aws"
package aws

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"sift/audit/remediation"
)

//go:embed remediations.json
var remediationsData []byte

func init() {
	var set remediation.TemplateSet
	if err := json.Unmarshal(remediationsData, &set); err != nil {
		panic(fmt.Sprintf("aws: failed to parse embedded remediations.json: %v", err))
	}
	remediation.RegisterTemplates(set)
}
