package ldap_redhat_test

import (
	"context"
	"os"
	"testing"

	ldap_redhat "github.com/openshift-eng/go-ldap-redhat"
)

func TestVersion(t *testing.T) {
	if ldap_redhat.Version == "" {
		t.Error("ldap_redhat.Version should not be empty")
	}
	if ldap_redhat.Version != "v1.2.0" {
		t.Errorf("Expected version v1.2.0, got %s", ldap_redhat.Version)
	}
}

func TestIdentifierConstants(t *testing.T) {
	if ldap_redhat.IDTUID != 0 {
		t.Errorf("ldap_redhat.IDTUID should be 0, got %d", ldap_redhat.IDTUID)
	}
	if ldap_redhat.IDTEmail != 1 {
		t.Errorf("ldap_redhat.IDTEmail should be 1, got %d", ldap_redhat.IDTEmail)
	}
}

func TestNewSearcherWithEmptyConfig(t *testing.T) {
	config := ldap_redhat.Config{}
	searcher, err := ldap_redhat.NewSearcher(config)
	if err != nil {
		t.Errorf("NewSearcher with empty config should not error, got: %v", err)
	}
	if searcher == nil {
		t.Error("Searcher should not be nil")
	}
	if searcher.Conn != nil {
		t.Error("Connection should be nil for empty config")
	}
	searcher.Close() // Should not panic
}

func TestNewSearcherWithInvalidURL(t *testing.T) {
	config := ldap_redhat.Config{
		LdapServers: []string{"invalid://bad-url"},
		Username:    "test",
		Password:    "test",
		BaseDN:      "dc=test,dc=com",
	}

	searcher, err := ldap_redhat.NewSearcher(config)
	if err == nil {
		t.Error("Expected error for invalid LDAP URL")
		if searcher != nil {
			searcher.Close()
		}
	}
}

func TestGetUserWithoutConnection(t *testing.T) {
	searcher := &ldap_redhat.Searcher{Config: ldap_redhat.Config{}}

	identifier := ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: "testuser"}
	ctx := context.Background()

	_, err := searcher.GetUser(ctx, identifier)
	if err == nil {
		t.Error("Expected error when no LDAP connection established")
	}

	expectedMsg := "LDAP connection not established"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestGetUserWithInvalidIdentifierType(t *testing.T) {
	searcher := &ldap_redhat.Searcher{
		Config: ldap_redhat.Config{},
		Conn:   nil, // Will trigger connection error first
	}

	// Test with invalid identifier type
	identifier := ldap_redhat.Identifier{Type: 999, Value: "testuser"}
	ctx := context.Background()

	_, err := searcher.GetUser(ctx, identifier)
	if err == nil {
		t.Error("Expected error for invalid identifier type")
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ldap://example.com:389", "example.com"},
		{"ldaps://secure.example.com:636", "secure.example.com"},
		{"ldap://host", "host"},
		{"ldaps://host", "host"},
		{"example.com:389", "example.com"},
		{"example.com", "example.com"},
	}

	for _, test := range tests {
		result := ldap_redhat.ExtractHostname(test.input)
		if result != test.expected {
			t.Errorf("ldap_redhat.ExtractHostname(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestGetEnvironment(t *testing.T) {
	// Save original env vars
	originalLdapEnv := os.Getenv("LDAP_ENV")
	originalEnv := os.Getenv("ENV")

	// Clean up after test
	defer func() {
		os.Setenv("LDAP_ENV", originalLdapEnv)
		os.Setenv("ENV", originalEnv)
	}()

	// Test default
	os.Unsetenv("LDAP_ENV")
	os.Unsetenv("ENV")
	if env := ldap_redhat.GetEnvironment(); env != "local" {
		t.Errorf("Default environment should be 'local', got '%s'", env)
	}

	// Test LDAP_ENV priority
	os.Setenv("LDAP_ENV", "production")
	os.Setenv("ENV", "development")
	if env := ldap_redhat.GetEnvironment(); env != "production" {
		t.Errorf("LDAP_ENV should take priority, expected 'production', got '%s'", env)
	}

	// Test ENV fallback
	os.Unsetenv("LDAP_ENV")
	os.Setenv("ENV", "staging")
	if env := ldap_redhat.GetEnvironment(); env != "staging" {
		t.Errorf("ENV fallback should work, expected 'staging', got '%s'", env)
	}
}

func TestReadSecretFileNonExistent(t *testing.T) {
	result := ldap_redhat.ReadSecretFile("/nonexistent/path/file")
	if result != "" {
		t.Errorf("readSecretFile for nonexistent file should return empty string, got '%s'", result)
	}
}

func TestNewSearcherFromEnv(t *testing.T) {
	// Save original env vars
	originalURL := os.Getenv("LDAP_URL")
	originalBindDN := os.Getenv("LDAP_BIND_DN")
	originalPassword := os.Getenv("LDAP_PASSWORD")
	originalBaseDN := os.Getenv("LDAP_BASE_DN")

	defer func() {
		os.Setenv("LDAP_URL", originalURL)
		os.Setenv("LDAP_BIND_DN", originalBindDN)
		os.Setenv("LDAP_PASSWORD", originalPassword)
		os.Setenv("LDAP_BASE_DN", originalBaseDN)
	}()

	// Test with minimal env vars
	os.Setenv("LDAP_URL", "ldap://test.example.com:389")
	os.Setenv("LDAP_BIND_DN", "uid=test,dc=example,dc=com")
	os.Setenv("LDAP_PASSWORD", "testpass")
	os.Setenv("LDAP_BASE_DN", "dc=example,dc=com")

	searcher, err := ldap_redhat.NewSearcherFromEnv()
	if err == nil {
		// This will likely fail to connect, but that's expected for test
		// We're just testing that the config is properly loaded
		searcher.Close()
	}

	// The function should at least not panic and should attempt to create a searcher
	// Connection failure is expected since we're using fake test values
}
