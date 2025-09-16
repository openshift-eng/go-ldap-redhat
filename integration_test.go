package ldap_redhat

import (
	"context"
	"os"
	"testing"
	"time"
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
	searcher, err := NewSearcherFromEnv()
	if err != nil {
		t.Fatalf("Failed to create searcher from env: %v", err)
	}
	defer searcher.Close()

	// Test search by known user (if TEST_LDAP_UID is set)
	if testUID := os.Getenv("TEST_LDAP_UID"); testUID != "" {
		t.Run("SearchByUID", func(t *testing.T) {
			identifier := Identifier{Type: IDTUID, Value: testUID}
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
			identifier := Identifier{Type: IDTEmail, Value: testEmail}
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
		identifier := Identifier{Type: IDTUID, Value: "nonexistent-user-12345"}
		_, err := searcher.GetUser(ctx, identifier)
		if err == nil {
			t.Error("Expected error for nonexistent user")
		}

		expectedMsg := "user not found in LDAP directory: nonexistent-user-12345"
		if err.Error() != expectedMsg {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})
}

// TestLDAPConnection tests basic LDAP connectivity
func TestLDAPConnection(t *testing.T) {
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping connection test: LDAP_URL not set")
	}

	config := Config{
		LdapServers: []string{os.Getenv("LDAP_URL")},
		Username:    os.Getenv("LDAP_BIND_DN"),
		Password:    getPasswordFromEnv(),
		BaseDN:      os.Getenv("LDAP_BASE_DN"),
		UseStartTLS: os.Getenv("LDAP_STARTTLS") == "true",
		VerifySSL:   false, // Internal Red Hat LDAP
	}

	if config.Password == "" {
		t.Skip("Skipping connection test: No password available")
	}

	searcher, err := NewSearcher(config)
	if err != nil {
		t.Fatalf("Failed to create searcher: %v", err)
	}
	defer searcher.Close()

	// If we get here, connection was successful
	t.Log("LDAP connection successful")

	if searcher.conn == nil {
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

	searcher, err := NewSearcherFromEnv()
	if err != nil {
		b.Fatalf("Failed to create searcher: %v", err)
	}
	defer searcher.Close()

	identifier := Identifier{Type: IDTUID, Value: testUID}
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, err := searcher.GetUser(ctx, identifier)
		if err != nil {
			b.Fatalf("Search failed: %v", err)
		}
	}
}
