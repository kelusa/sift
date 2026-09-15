package remediation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"sift/audit"
)

// Template defines a remediation recommendation for a module/service/check.
// Providers register their own template sets via RegisterTemplates.
type Template struct {
	Action     string `json:"action"`
	Command    string `json:"command"`
	Confidence string `json:"confidence"`
	ActionRisk string `json:"action_risk"`
}

// TemplateSet is the nested registration shape: module -> service -> check -> Template.
type TemplateSet map[string]map[string]map[string]Template

var (
	mu           sync.Mutex
	table        = TemplateSet{}
	overrideOnce sync.Once
)

// RegisterTemplates merges a provider's remediation templates into the global
// table. Safe to call from init() in any order; later registrations for the
// same module/service/check win. Provider packages (e.g. audit/aws) call this.
func RegisterTemplates(set TemplateSet) {
	mu.Lock()
	defer mu.Unlock()
	for module, svcs := range set {
		if table[module] == nil {
			table[module] = map[string]map[string]Template{}
		}
		for svc, checks := range svcs {
			if table[module][svc] == nil {
				table[module][svc] = map[string]Template{}
			}
			for check, tmpl := range checks {
				table[module][svc][check] = tmpl
			}
		}
	}
}

// loadOverride merges ~/.sift/remediations.json on top of registered templates.
// Applied lazily (once) so it always wins over provider init() registrations
// regardless of package initialization order.
func loadOverride() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	data, err := os.ReadFile(filepath.Join(home, ".sift", "remediations.json"))
	if err != nil {
		return
	}
	var set TemplateSet
	if json.Unmarshal(data, &set) != nil {
		return
	}
	RegisterTemplates(set)
}

// Recommend returns a Remediation for the given module/service/check, or nil if none defined.
func Recommend(module, service, check, resourceID, evidence string) *audit.Remediation {
	overrideOnce.Do(loadOverride)

	mu.Lock()
	defer mu.Unlock()

	mod, ok := table[module]
	if !ok {
		return nil
	}
	svc, ok := mod[service]
	if !ok {
		return nil
	}
	tmpl, ok := svc[check]
	if !ok {
		return nil
	}

	cmd := strings.ReplaceAll(tmpl.Command, "{{.ResourceID}}", resourceID)

	return &audit.Remediation{
		Action:     tmpl.Action,
		Command:    cmd,
		Evidence:   evidence,
		Confidence: tmpl.Confidence,
		ActionRisk: tmpl.ActionRisk,
	}
}
