package audit

import "sort"

var registry = map[string][]Checker{}

func Register(module string, c Checker) {
	registry[module] = append(registry[module], c)
}

// RegisterAWS registers an AWS-native checker (one that takes an aws.Config)
// under the given module, adapting it to the provider-neutral CheckFn.
// Existing AWS service files call this from their init() so their function
// bodies stay unchanged.
func RegisterAWS(module, name string, fn AWSCheckFn) {
	registry[module] = append(registry[module], Checker{Name: name, Fn: wrapAWS(fn)})
}

func CheckersFor(module string) []Checker {
	return registry[module]
}

func ValidServices(module string) map[string]bool {
	m := make(map[string]bool)
	for _, c := range registry[module] {
		m[c.Name] = true
	}
	return m
}

func ServiceNames(module string) []string {
	checkers := registry[module]
	names := make([]string, len(checkers))
	for i, c := range checkers {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}
