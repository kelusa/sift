package security

import "testing"

func TestEC2Risk(t *testing.T) {
	tests := []struct {
		name string
		inst ec2Instance
		want string
	}{
		{"public+open=CRITICAL", ec2Instance{publicIP: true, openToWorld: true}, "CRITICAL"},
		{"open only=HIGH", ec2Instance{openToWorld: true}, "HIGH"},
		{"public+imdsv1=HIGH", ec2Instance{publicIP: true, imdsV1: true}, "HIGH"},
		{"public only=MEDIUM", ec2Instance{publicIP: true}, "MEDIUM"},
		{"imdsv1 only=MEDIUM", ec2Instance{imdsV1: true}, "MEDIUM"},
		{"clean=MINIMAL", ec2Instance{}, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ec2Risk(tt.inst); got != tt.want {
				t.Errorf("ec2Risk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRDSRisk(t *testing.T) {
	tests := []struct {
		name        string
		public      bool
		encrypted   bool
		backup      int32
		delProtect  bool
		multiAZ     bool
		autoUpgrade bool
		want        string
	}{
		{"public+unencrypted=CRITICAL", true, false, 7, true, true, true, "CRITICAL"},
		{"public+encrypted=HIGH", true, true, 7, true, true, true, "HIGH"},
		{"unencrypted=HIGH", false, false, 7, true, true, true, "HIGH"},
		{"low backup=MEDIUM", false, true, 3, true, true, true, "MEDIUM"},
		{"no del protect=MEDIUM", false, true, 7, false, true, true, "MEDIUM"},
		{"no multi-az=LOW", false, true, 7, true, false, true, "LOW"},
		{"no auto upgrade=LOW", false, true, 7, true, true, false, "LOW"},
		{"all good=MINIMAL", false, true, 7, true, true, true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rdsRisk(
				tt.public,
				tt.encrypted,
				tt.backup,
				tt.delProtect,
				tt.multiAZ,
				tt.autoUpgrade,
				7,
			)
			if got != tt.want {
				t.Errorf("rdsRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEKSRisk(t *testing.T) {
	tests := []struct {
		name            string
		publicEP        bool
		privateEP       bool
		secretsEnc      bool
		hasDisabledLogs bool
		want            string
	}{
		{"public+no private+no enc=CRITICAL", true, false, false, false, "CRITICAL"},
		{"public+no private+enc=HIGH", true, false, true, false, "HIGH"},
		{"public+private=MEDIUM", true, true, true, false, "MEDIUM"},
		{"private+no secrets enc=LOW", false, true, false, false, "LOW"},
		{"private+disabled logs=LOW", false, true, true, true, "LOW"},
		{"all good=MINIMAL", false, true, true, false, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eksRisk(tt.publicEP, tt.privateEP, tt.secretsEnc, tt.hasDisabledLogs)
			if got != tt.want {
				t.Errorf("eksRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSagemakerRisk(t *testing.T) {
	tests := []struct {
		name           string
		directInternet bool
		publicSubnet   bool
		sgOpen         bool
		want           string
	}{
		{"direct internet=HIGH", true, false, false, "HIGH"},
		{"public+open sg=HIGH", false, true, true, "HIGH"},
		{"public subnet only=MEDIUM", false, true, false, "MEDIUM"},
		{"open sg only=LOW", false, false, true, "LOW"},
		{"clean=MINIMAL", false, false, false, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sagemakerRisk(tt.directInternet, tt.publicSubnet, tt.sgOpen)
			if got != tt.want {
				t.Errorf("sagemakerRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestELBRisk(t *testing.T) {
	tests := []struct {
		name          string
		scheme        string
		dbPortExposed bool
		openToWorld   bool
		want          string
	}{
		{"internal=MINIMAL", "internal", true, true, "MINIMAL"},
		{"internet+db+open=CRITICAL", "internet-facing", true, true, "CRITICAL"},
		{"internet+open=HIGH", "internet-facing", false, true, "HIGH"},
		{"internet+db=MEDIUM", "internet-facing", true, false, "MEDIUM"},
		{"internet only=LOW", "internet-facing", false, false, "LOW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elbRisk(tt.scheme, tt.dbPortExposed, tt.openToWorld)
			if got != tt.want {
				t.Errorf("elbRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSecretsRisk(t *testing.T) {
	tests := []struct {
		name             string
		rotationEnabled  bool
		rotationOverdue  bool
		daysSinceRotated int
		want             string
	}{
		{"no rotation+never rotated=HIGH", false, false, -1, "HIGH"},
		{"no rotation=MEDIUM", false, false, 30, "MEDIUM"},
		{"rotation overdue=MEDIUM", true, true, 120, "MEDIUM"},
		{"rotation enabled+current=MINIMAL", true, false, 20, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secretsRisk(tt.rotationEnabled, tt.rotationOverdue, tt.daysSinceRotated)
			if got != tt.want {
				t.Errorf("secretsRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestGlueCatalogRisk(t *testing.T) {
	tests := []struct {
		name             string
		catalogEncrypted bool
		connEncrypted    bool
		want             string
	}{
		{"bot unencrypted=HIGH", false, false, "HIGH"},
		{"partial catalog=MEDIUM", true, false, "MEDIUM"},
		{"partial conn=MEDIUM", false, true, "MEDIUM"},
		{"both encrypted=MINIMAL", true, true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := glueCatalogRisk(tt.catalogEncrypted, tt.connEncrypted)
			if got != tt.want {
				t.Errorf("glueCatalogRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBaselineRisk(t *testing.T) {
	tests := []struct {
		check string
		want  string
	}{
		{"no_trails", "CRITICAL"},
		{"logging_disabled", "CRITICAL"},
		{"not_enabled", "CRITICAL"},
		{"detector_disabled", "CRITICAL"},
		{"single_region", "HIGH"},
		{"no_log_validation", "MEDIUM"},
		{"everything_fine", "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.check, func(t *testing.T) {
			if got := baselineRisk(tt.check); got != tt.want {
				t.Errorf("baselineRisk(%q) = %s, want %s", tt.check, got, tt.want)
			}
		})
	}
}

func TestBackupRisk(t *testing.T) {
	tests := []struct {
		name      string
		encrypted bool
		want      string
	}{
		{"unencrypted=HIGH", false, "HIGH"},
		{"encrypted=MINIMAL", true, "MINIMAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := backupRisk(tt.encrypted); got != tt.want {
				t.Errorf("backupRisk() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestStatusFromRisk(t *testing.T) {
	tests := []struct {
		risk string
		want string
	}{
		{"MINIMAL", "PASS"},
		{"LOW", "FAIL"},
		{"MEDIUM", "FAIL"},
		{"HIGH", "FAIL"},
		{"CRITICAL", "FAIL"},
	}
	for _, tt := range tests {
		t.Run(tt.risk, func(t *testing.T) {
			if got := statusFromRisk(tt.risk); got != tt.want {
				t.Errorf("statusFromRisk(%q) = %s, want %s", tt.risk, got, tt.want)
			}
		})
	}
}
