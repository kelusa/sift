package pricing

import "strings"

// MapToGraviton maps an x86 instance type to its Graviton equivalent.
// Returns empty string if already Graviton or no mapping exists.
func MapToGraviton(instanceType string) string {
	parts := strings.Split(instanceType, ".")
	if len(parts) != 2 {
		return ""
	}
	family := parts[0]
	size := parts[1]

	if strings.HasSuffix(family, "g") || strings.HasSuffix(family, "gd") {
		return ""
	}

	gravitonFamily := mapFamily(family)
	if gravitonFamily == "" {
		return ""
	}

	return gravitonFamily + "." + size
}

func mapFamily(family string) string {
	switch family {
	case "m7i", "m7a", "m6i", "m6a", "m5", "m5a", "m5n":
		return "m7g"
	case "c7i", "c7a", "c6i", "c6a", "c5", "c5a", "c5n":
		return "c7g"
	case "r7i", "r7a", "r6i", "r6a", "r5", "r5a", "r5n":
		return "r7g"
	case "t3", "t3a", "t2":
		return "t4g"
	case "m4":
		return "m7g"
	case "c4":
		return "c7g"
	case "r4":
		return "r7g"
	default:
		return ""
	}
}

// GravitonSavings calculates monthly savings from switching to Graviton.
func GravitonSavings(
	instanceType string,
) (gravitonType string, currentCost, gravitonCost, savings float64) {
	gravitonType = MapToGraviton(instanceType)
	if gravitonType == "" {
		return "", 0, 0, 0
	}
	currentCost = EC2Monthly(instanceType)
	gravitonCost = EC2Monthly(gravitonType)
	if currentCost == 0 || gravitonCost == 0 {
		return "", 0, 0, 0
	}
	savings = currentCost - gravitonCost
	return gravitonType, currentCost, gravitonCost, savings
}

// RDSGravitonSavings calculates monthly savings for an RDS instance class (db.X.size).
func RDSGravitonSavings(
	instanceType string,
) (gravitonType string, currentCost, gravitonCost, savings float64) {
	base := strings.TrimPrefix(instanceType, "db.")
	gravitonBare := MapToGraviton(base)
	if gravitonBare == "" {
		return "", 0, 0, 0
	}
	gravitonType = "db." + gravitonBare
	currentCost = RDSMonthly(instanceType)
	gravitonCost = RDSMonthly(gravitonType)
	if currentCost == 0 || gravitonCost == 0 {
		return "", 0, 0, 0
	}
	savings = currentCost - gravitonCost
	return gravitonType, currentCost, gravitonCost, savings
}
