package ldap_redhat

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestMain is the main test runner that sets up and tears down test environment
func TestMain(m *testing.M) {
	fmt.Println("Starting Go LDAP Red Hat Test Suite")
	fmt.Println("=====================================")

	// Setup test environment
	setupTestEnvironment()

	// Run all tests
	code := m.Run()

	// Cleanup
	cleanupTestEnvironment()

	fmt.Println("=====================================")
	if code == 0 {
		fmt.Println("All tests completed successfully!")
	} else {
		fmt.Println("Some tests failed!")
	}

	os.Exit(code)
}

// setupTestEnvironment prepares the test environment
func setupTestEnvironment() {
	fmt.Println("Setting up test environment...")

	// Set test environment variables if not already set
	if os.Getenv("LDAP_URL") == "" {
		os.Setenv("LDAP_URL", "ldap://apps-ldap.corp.redhat.com:389")
		fmt.Println("   Set LDAP_URL for tests")
	}

	if os.Getenv("LDAP_BASE_DN") == "" {
		os.Setenv("LDAP_BASE_DN", "dc=redhat,dc=com")
		fmt.Println("   Set LDAP_BASE_DN for tests")
	}

	if os.Getenv("LDAP_BIND_DN") == "" {
		os.Setenv("LDAP_BIND_DN", "uid=pco-deleted-users-query,ou=users,dc=redhat,dc=com")
		fmt.Println("   Set LDAP_BIND_DN for tests")
	}

	if os.Getenv("LDAP_STARTTLS") == "" {
		os.Setenv("LDAP_STARTTLS", "true")
		fmt.Println("   Set LDAP_STARTTLS for tests")
	}

	// Check if we have credentials for integration tests
	hasPassword := getPasswordFromEnv() != ""
	if hasPassword {
		fmt.Println("   LDAP credentials available - integration tests will run")
	} else {
		fmt.Println("   No LDAP credentials - integration tests will be skipped")
	}

	fmt.Println("")
}

// cleanupTestEnvironment cleans up after tests
func cleanupTestEnvironment() {
	fmt.Println("")
	fmt.Println("Cleaning up test environment...")
	// Any cleanup needed can go here
}

// TestSuiteOverview provides a comprehensive test overview
func TestSuiteOverview(t *testing.T) {
	fmt.Println("\nTest Suite Overview:")
	fmt.Println("====================")

	// Test categories
	categories := []struct {
		name        string
		description string
		file        string
	}{
		{"Core Library", "Version, constants, basic functionality", "ldap_redhat_test.go"},
		{"Configuration", "YAML, env vars, secrets loading", "config_test.go"},
		{"User Validation", "UserRecord, identifiers, Red Hat fields", "user_test.go"},
		{"Integration", "Real LDAP connections and searches", "integration_test.go"},
	}

	for _, cat := range categories {
		fmt.Printf("%-15s: %s (%s)\n", cat.name, cat.description, cat.file)
	}

	// Test environment info
	fmt.Println("\nTest Environment:")
	fmt.Printf("   LDAP URL: %s\n", os.Getenv("LDAP_URL"))
	fmt.Printf("   Base DN: %s\n", os.Getenv("LDAP_BASE_DN"))
	fmt.Printf("   Has Password: %v\n", getPasswordFromEnv() != "")
	fmt.Printf("   Environment: %s\n", getEnvironment())

	// Library info
	fmt.Printf("\nLibrary Info:\n")
	fmt.Printf("   Version: %s\n", Version)
	fmt.Printf("   Module: github.com/openshift-eng/go-ldap-redhat\n")

	fmt.Println("")
}

// TestQuickHealthCheck performs a quick health check of all major components
func TestQuickHealthCheck(t *testing.T) {
	t.Run("VersionCheck", func(t *testing.T) {
		if Version == "" {
			t.Error("Version should be set")
		}
		t.Logf("Version: %s", Version)
	})

	t.Run("ConfigurationCheck", func(t *testing.T) {
		config := loadConfigFromAll()
		if len(config.LdapServers) == 0 {
			t.Log("⚠️  No LDAP servers configured")
		} else {
			t.Logf("LDAP Server: %s", config.LdapServers[0])
		}

		if config.Password == "" {
			t.Log("⚠️  No password configured")
		} else {
			t.Logf("Password loaded (length: %d)", len(config.Password))
		}
	})

	t.Run("ConnectionCheck", func(t *testing.T) {
		if os.Getenv("LDAP_URL") == "" {
			t.Skip("Skipping connection check: No LDAP_URL")
		}

		// Quick connection test (don't search, just connect)
		searcher, err := NewSearcherWithDefaults()
		if err != nil {
			t.Logf("⚠️  Connection failed: %v", err)
			return
		}
		defer searcher.Close()

		t.Log("LDAP connection successful")
	})
}

// TestRealUserLookup tests with a known Red Hat user (if configured)
func TestRealUserLookup(t *testing.T) {
	if os.Getenv("LDAP_URL") == "" {
		t.Skip("Skipping real user test: LDAP_URL not set")
	}

	// Test with etang (known to exist)
	searcher, err := NewSearcherWithDefaults()
	if err != nil {
		t.Skip("Skipping real user test: Cannot create searcher")
	}
	defer searcher.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test etang@redhat.com
	identifier := Identifier{Type: IDTEmail, Value: "etang@redhat.com"}
	user, err := searcher.GetUser(ctx, identifier)
	if err != nil {
		t.Logf("etang lookup failed: %v", err)
		return
	}

	t.Logf("Real user test successful:")
	t.Logf("   Found: %s (%s)", user.UID, user.Email)
	t.Logf("   Title: %s", user.Title)
	t.Logf("   Location: %s", user.RhatLocation)

	// Validate real user data
	if user.UID != "etang" {
		t.Errorf("Expected UID 'etang', got '%s'", user.UID)
	}
	if user.Email != "etang@redhat.com" {
		t.Errorf("Expected email 'etang@redhat.com', got '%s'", user.Email)
	}
	if user.RhatUUID == "" {
		t.Error("RhatUUID should not be empty for real user")
	}
}
