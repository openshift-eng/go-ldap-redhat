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
