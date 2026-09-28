package triage

import "testing"

func TestTriageRisk(t *testing.T) {
	tests := []struct {
		name        string
		openToWorld bool
		imdsV1      bool
		iamRisk     string
		connCount   int
		want        string
	}{
		{"public conns + open", true, false, "", 5, "CRITICAL"},
		{"public conns only", false, false, "", 3, "HIGH"},
		{"iam HIGH + open", true, false, "HIGH", 0, "HIGH"},
		{"open to world", true, false, "", 0, "MEDIUM"},
		{"imdsv1", false, true, "", 0, "MEDIUM"},
		{"clean", false, false, "", 0, "LOW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triageRisk(tt.openToWorld, tt.imdsV1, tt.iamRisk, tt.connCount); got != tt.want {
				t.Errorf("triageRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}
