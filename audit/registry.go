package audit

import "sort"

// registry keys checkes by "provider:module" so that the same module name
// (e.g. "governance") can exist independently per provider without collision.
var registry = map[string][]Checker{}

func regKey(provider, module string) string { return provider + ":" + module }

// Register adds a provider-neutral checker under the given provider+module.
// AWS checkers register via awsreg.Register (which adapts an aws.Config-based
// checker and calls this); Non-AWS providers (e.g. Aria) call this directly.
func Register(provider, module string, c Checker) {
	registry[regKey(provider, module)] = append(registry[regKey(provider, module)], c)
}

func CheckersFor(provider, module string) []Checker {
	return registry[regKey(provider, module)]
}

func ValidServices(provider, module string) map[string]bool {
	m := make(map[string]bool)
	for _, c := range registry[regKey(provider, module)] {
		m[c.Name] = true
	}
	return m
}

func ServiceNames(provider, module string) []string {
	checkers := registry[regKey(provider, module)]
	names := make([]string, len(checkers))
	for i, c := range checkers {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}
