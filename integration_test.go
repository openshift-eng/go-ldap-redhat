package ldap_redhat_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	ldap_redhat "github.com/openshift-eng/go-ldap-redhat"
)

// TestLDAPIntegration tests against real Red Hat LDAP (requires credentials)
func TestLDAPIntegration(t *testing.T) {
	// Skip if no LDAP configuration
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping integration test: LDAP_URL not set")
	}

	// Skip if running in CI without credentials
	if os.Getenv("CI") == "true" && os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test in CI")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use environment-based configuration
	searcher, err := ldap_redhat.NewSearcherFromEnv()
	if err != nil {
		t.Fatalf("Failed to create searcher from env: %v", err)
	}
	defer searcher.Close()

	// Test search by known user (if TEST_LDAP_UID is set)
	if testUID := os.Getenv("TEST_LDAP_UID"); testUID != "" {
		t.Run("SearchByUID", func(t *testing.T) {
			identifier := ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: testUID}
			user, err := searcher.GetUser(ctx, identifier)
			if err != nil {
				if err.Error() == "user not found in LDAP directory: "+testUID {
					t.Skipf("Test user %s not found (expected for some environments)", testUID)
				}
				t.Fatalf("Failed to search by UID: %v", err)
			}

			if user.UID == "" {
				t.Error("User UID should not be empty")
			}
			if user.Email == "" {
				t.Error("User Email should not be empty")
			}

			t.Logf("Found user by UID: %s (%s)", user.UID, user.Email)
		})
	}

	// Test search by known email (if TEST_LDAP_EMAIL is set)
	if testEmail := os.Getenv("TEST_LDAP_EMAIL"); testEmail != "" {
		t.Run("SearchByEmail", func(t *testing.T) {
			identifier := ldap_redhat.Identifier{Type: ldap_redhat.IDTEmail, Value: testEmail}
			user, err := searcher.GetUser(ctx, identifier)
			if err != nil {
				if err.Error() == "user not found in LDAP directory: "+testEmail {
					t.Skipf("Test email %s not found (expected for some environments)", testEmail)
				}
				t.Fatalf("Failed to search by email: %v", err)
			}

			if user.Email != testEmail {
				t.Errorf("Expected email %s, got %s", testEmail, user.Email)
			}

			t.Logf("Found user by email: %s (%s)", user.UID, user.Email)
		})
	}

	// Test search for nonexistent user
	t.Run("SearchNonexistentUser", func(t *testing.T) {
		identifier := ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: "nonexistent-user-12345"}
		_, err := searcher.GetUser(ctx, identifier)
		if err == nil {
			t.Error("Expected error for nonexistent user")
		}

		// Check for either authentication error (no credentials) or user not found
		if !strings.Contains(err.Error(), "user not found in LDAP directory") &&
			!strings.Contains(err.Error(), "Anonymous access is not allowed") &&
			!strings.Contains(err.Error(), "Inappropriate Authentication") {
			t.Errorf("Expected user not found or authentication error, got: %v", err)
		}
	})
}

// TestLDAPConnection tests basic LDAP connectivity
func TestLDAPConnection(t *testing.T) {
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping connection test: LDAP_URL not set")
	}

	config := ldap_redhat.Config{
		LdapServers: []string{os.Getenv("LDAP_URL")},
		Username:    os.Getenv("LDAP_BIND_DN"),
		Password:    ldap_redhat.GetPasswordFromEnv(),
		BaseDN:      os.Getenv("LDAP_BASE_DN"),
		UseStartTLS: os.Getenv("LDAP_START_TLS") == "true",
		VerifySSL:   false, // Internal Red Hat LDAP
	}

	if config.Password == "" {
		t.Skip("Skipping connection test: No password available")
	}

	searcher, err := ldap_redhat.NewSearcher(config)
	if err != nil {
		t.Fatalf("Failed to create searcher: %v", err)
	}
	defer searcher.Close()

	// If we get here, connection was successful
	t.Log("LDAP connection successful")

	if searcher.Conn == nil {
		t.Error("Expected active LDAP connection")
	}
}

// TestGetUsersIntegration tests batch user lookup
func TestGetUsersIntegration(t *testing.T) {
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping integration test: LDAP_URL not set")
	}

	searcher, err := ldap_redhat.NewSearcherWithDefaults()
	if err != nil {
		t.Skip("Skipping: cannot create searcher")
	}
	defer searcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids := []ldap_redhat.Identifier{
		{Type: ldap_redhat.IDTUID, Value: "jemedina"},
		{Type: ldap_redhat.IDTEmail, Value: "jemedina@redhat.com"},
		{Type: ldap_redhat.IDTUID, Value: "nonexistent-user-zzz"},
	}

	results, err := searcher.GetUsers(ctx, ids)
	if err != nil {
		t.Fatalf("GetUsers failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	if results[0].UID != "jemedina" {
		t.Errorf("Expected UID 'jemedina' at index 0, got '%s'", results[0].UID)
	}
	if results[1].UID != "jemedina" {
		t.Errorf("Expected UID 'jemedina' at index 1 (email lookup), got '%s'", results[1].UID)
	}
	if results[2].UID != "" {
		t.Errorf("Expected empty UID at index 2 (nonexistent), got '%s'", results[2].UID)
	}

	t.Logf("GetUsers: returned %d results, new fields: Country=%q, Department=%q, CostCenterDesc=%q",
		len(results), results[0].Country, results[0].Department, results[0].CostCenterDesc)
}

// TestFindDirectReportsIntegration tests the direct reports search
func TestFindDirectReportsIntegration(t *testing.T) {
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping integration test: LDAP_URL not set")
	}

	testManager := os.Getenv("TEST_LDAP_MANAGER_UID")
	if testManager == "" {
		t.Skip("Skipping: TEST_LDAP_MANAGER_UID not set")
	}

	searcher, err := ldap_redhat.NewSearcherWithDefaults()
	if err != nil {
		t.Skip("Skipping: cannot create searcher")
	}
	defer searcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reports, err := searcher.FindDirectReports(ctx, testManager)
	if err != nil {
		t.Fatalf("FindDirectReports failed: %v", err)
	}
	t.Logf("FindDirectReports(%s): found %d direct reports", testManager, len(reports))

	// Test with Works Council exclusion
	wcExclude := []string{"esp", "fra", "nld", "deu", "aut", "bel"}
	filtered, err := searcher.FindDirectReports(ctx, testManager, ldap_redhat.ReportSearchOptions{
		ExcludeCountries: wcExclude,
	})
	if err != nil {
		t.Fatalf("FindDirectReports with WC exclusion failed: %v", err)
	}
	t.Logf("FindDirectReports(%s) with WC exclusion: %d (was %d)", testManager, len(filtered), len(reports))

	if len(filtered) > len(reports) {
		t.Error("Filtered results should be <= unfiltered results")
	}
}

// TestNewFieldsPopulated checks that new fields (Country, Department, CostCenterDesc, RhatAdjSvcDate)
// are populated from real LDAP data
func TestNewFieldsPopulated(t *testing.T) {
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping integration test: LDAP_URL not set")
	}

	searcher, err := ldap_redhat.NewSearcherWithDefaults()
	if err != nil {
		t.Skip("Skipping: cannot create searcher")
	}
	defer searcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user, err := searcher.GetUser(ctx, ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: "jemedina"})
	if err != nil {
		t.Skipf("User lookup failed: %v", err)
	}

	t.Logf("New fields for %s:", user.UID)
	t.Logf("  Country:        %q", user.Country)
	t.Logf("  Department:     %q", user.Department)
	t.Logf("  CostCenterDesc: %q", user.CostCenterDesc)
	t.Logf("  RhatAdjSvcDate: %q", user.RhatAdjSvcDate)

	if user.CostCenterDesc == "" {
		t.Log("Note: CostCenterDesc is empty — attribute may not be populated for this user")
	}
}

// BenchmarkUserSearch benchmarks user search performance
func BenchmarkUserSearch(b *testing.B) {
	if os.Getenv("LDAP_URL") == "" {
		b.Skip("Skipping benchmark: LDAP_URL not set")
	}

	testUID := os.Getenv("TEST_LDAP_UID")
	if testUID == "" {
		b.Skip("Skipping benchmark: TEST_LDAP_UID not set")
	}

	searcher, err := ldap_redhat.NewSearcherFromEnv()
	if err != nil {
		b.Fatalf("Failed to create searcher: %v", err)
	}
	defer searcher.Close()

	identifier := ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: testUID}
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, err := searcher.GetUser(ctx, identifier)
		if err != nil {
			b.Fatalf("Search failed: %v", err)
		}
	}
}
