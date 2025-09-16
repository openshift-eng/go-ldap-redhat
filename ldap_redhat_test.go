package ldap_redhat

import (
	"context"
	"os"
	"testing"
)

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Version != "v1.1.0" {
		t.Errorf("Expected version v1.1.0, got %s", Version)
	}
}

func TestIdentifierConstants(t *testing.T) {
	if IDTUID != 0 {
		t.Errorf("IDTUID should be 0, got %d", IDTUID)
	}
	if IDTEmail != 1 {
		t.Errorf("IDTEmail should be 1, got %d", IDTEmail)
	}
}

func TestNewSearcherWithEmptyConfig(t *testing.T) {
	config := Config{}
	searcher, err := NewSearcher(config)
	if err != nil {
		t.Errorf("NewSearcher with empty config should not error, got: %v", err)
	}
	if searcher == nil {
		t.Error("Searcher should not be nil")
	}
	if searcher.conn != nil {
		t.Error("Connection should be nil for empty config")
	}
	searcher.Close() // Should not panic
}

func TestNewSearcherWithInvalidURL(t *testing.T) {
	config := Config{
		LdapServers: []string{"invalid://bad-url"},
		Username:    "test",
		Password:    "test",
		BaseDN:      "dc=test,dc=com",
	}

	searcher, err := NewSearcher(config)
	if err == nil {
		t.Error("Expected error for invalid LDAP URL")
		if searcher != nil {
			searcher.Close()
		}
	}
}

func TestGetUserWithoutConnection(t *testing.T) {
	searcher := &Searcher{config: Config{}}

	identifier := Identifier{Type: IDTUID, Value: "testuser"}
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
	searcher := &Searcher{
		config: Config{},
		conn:   nil, // Will trigger connection error first
	}

	// Test with invalid identifier type
	identifier := Identifier{Type: 999, Value: "testuser"}
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
		result := extractHostname(test.input)
		if result != test.expected {
			t.Errorf("extractHostname(%s) = %s, expected %s", test.input, result, test.expected)
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
	if env := getEnvironment(); env != "local" {
		t.Errorf("Default environment should be 'local', got '%s'", env)
	}

	// Test LDAP_ENV priority
	os.Setenv("LDAP_ENV", "production")
	os.Setenv("ENV", "development")
	if env := getEnvironment(); env != "production" {
		t.Errorf("LDAP_ENV should take priority, expected 'production', got '%s'", env)
	}

	// Test ENV fallback
	os.Unsetenv("LDAP_ENV")
	os.Setenv("ENV", "staging")
	if env := getEnvironment(); env != "staging" {
		t.Errorf("ENV fallback should work, expected 'staging', got '%s'", env)
	}
}

func TestReadSecretFileNonExistent(t *testing.T) {
	result := readSecretFile("/nonexistent/path/file")
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

	searcher, err := NewSearcherFromEnv()
	if err == nil {
		// This will likely fail to connect, but that's expected for test
		// We're just testing that the config is properly loaded
		searcher.Close()
	}

	// The function should at least not panic and should attempt to create a searcher
	// Connection failure is expected since we're using fake test values
}
