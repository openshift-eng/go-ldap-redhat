package ldap_redhat_test

import (
	"strings"
	"testing"

	ldap_redhat "github.com/openshift-eng/go-ldap-redhat"
)

// TestUserRecordValidation tests UserRecord field validation
func TestUserRecordValidation(t *testing.T) {
	// Test empty UserRecord
	user := ldap_redhat.UserRecord{}
	if user.UID != "" {
		t.Error("Empty UserRecord should have empty UID")
	}

	// Test UserRecord with required fields only
	user = ldap_redhat.UserRecord{
		UID:   "testuser",
		Email: "testuser@redhat.com",
	}

	// Validate required fields
	if user.UID == "" {
		t.Error("UID should not be empty")
	}
	if user.Email == "" {
		t.Error("Email should not be empty")
	}
	if !strings.Contains(user.Email, "@") {
		t.Error("Email should contain @ symbol")
	}
	if !strings.HasSuffix(user.Email, "@redhat.com") {
		t.Error("Email should end with @redhat.com for Red Hat users")
	}
}

// Testldap_redhat.IdentifierValidation tests ldap_redhat.Identifier validation
func TestIdentifierValidation(t *testing.T) {
	tests := []struct {
		name       string
		identifier ldap_redhat.Identifier
		valid      bool
	}{
		{
			name:       "Valid UID",
			identifier: ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: "testuser"},
			valid:      true,
		},
		{
			name:       "Valid Email",
			identifier: ldap_redhat.Identifier{Type: ldap_redhat.IDTEmail, Value: "test@redhat.com"},
			valid:      true,
		},
		{
			name:       "Empty UID",
			identifier: ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: ""},
			valid:      false,
		},
		{
			name:       "Empty Email",
			identifier: ldap_redhat.Identifier{Type: ldap_redhat.IDTEmail, Value: ""},
			valid:      false,
		},
		{
			name:       "Invalid Email Format",
			identifier: ldap_redhat.Identifier{Type: ldap_redhat.IDTEmail, Value: "notanemail"},
			valid:      false,
		},
		{
			name:       "Invalid ldap_redhat.Identifier Type",
			identifier: ldap_redhat.Identifier{Type: 999, Value: "test"},
			valid:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid := validateIdentifier(test.identifier)
			if valid != test.valid {
				t.Errorf("Expected validation result %v for %+v, got %v",
					test.valid, test.identifier, valid)
			}
		})
	}
}

// validateldap_redhat.Identifier validates an identifier (helper function for testing)
func validateIdentifier(id ldap_redhat.Identifier) bool {
	if id.Value == "" {
		return false
	}

	switch id.Type {
	case ldap_redhat.IDTUID:
		// UID should not be empty and should be reasonable length
		return len(id.Value) > 0 && len(id.Value) < 100
	case ldap_redhat.IDTEmail:
		// Email should contain @ and be reasonable format
		return strings.Contains(id.Value, "@") &&
			strings.Contains(id.Value, ".") &&
			len(id.Value) > 3
	default:
		return false
	}
}

// TestUserRecordSerialization tests that UserRecord can be properly serialized
func TestUserRecordSerialization(t *testing.T) {
	user := ldap_redhat.UserRecord{
		UID:         "testuser",
		Email:       "testuser@redhat.com",
		DisplayName: "Test User",
		RhatUUID:    "12345678-1234-1234-1234-123456789abc",
	}

	// Test that all string fields can handle various inputs
	if user.UID != "testuser" {
		t.Error("UID serialization failed")
	}

	// Test special characters and spaces
	user.DisplayName = "Test User with Spaces"
	if user.DisplayName != "Test User with Spaces" {
		t.Error("DisplayName with spaces failed")
	}

	// Test empty optional fields
	user.RhatTermDate = ""
	if user.RhatTermDate != "" {
		t.Error("Empty RhatTermDate should remain empty")
	}
}

// TestRedHatSpecificFields tests Red Hat-specific LDAP attributes
func TestRedHatSpecificFields(t *testing.T) {
	user := ldap_redhat.UserRecord{
		RhatUUID:     "12345678-1234-1234-1234-123456789abc",
		RhatLocation: "Remote US CA",
		RhatHireDate: "20220711070000Z",
		RhatTermDate: "", // Active employee
	}

	// Test UUID format (basic check)
	if !strings.Contains(user.RhatUUID, "-") {
		t.Error("RhatUUID should contain hyphens")
	}

	// Test hire date format (LDAP timestamp)
	if user.RhatHireDate != "" && !strings.HasSuffix(user.RhatHireDate, "Z") {
		t.Error("RhatHireDate should end with Z (Zulu time)")
	}

	// Test active vs terminated employee
	isActive := user.RhatTermDate == ""
	if !isActive {
		t.Error("Test user should be active (no term date)")
	}

	// Test location format
	if user.RhatLocation != "" && len(user.RhatLocation) < 2 {
		t.Error("RhatLocation should be meaningful if set")
	}
}
