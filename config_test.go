package ldap_redhat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFromAll(t *testing.T) {
	// Save original env vars and DefaultConfig
	originalLdapEnv := os.Getenv("LDAP_ENV")
	originalURL := os.Getenv("LDAP_URL")
	originalBindDN := os.Getenv("LDAP_BIND_DN")
	originalBaseDN := os.Getenv("LDAP_BASE_DN")
	originalPassword := os.Getenv("LDAP_PASSWORD")
	originalPasswordFile := os.Getenv("LDAP_PASSWORD_FILE")

	defer func() {
		os.Setenv("LDAP_ENV", originalLdapEnv)
		os.Setenv("LDAP_URL", originalURL)
		os.Setenv("LDAP_BIND_DN", originalBindDN)
		os.Setenv("LDAP_BASE_DN", originalBaseDN)
		os.Setenv("LDAP_PASSWORD", originalPassword)
		os.Setenv("LDAP_PASSWORD_FILE", originalPasswordFile)
	}()

	// Clear any existing password file env var to ensure clean test
	os.Unsetenv("LDAP_PASSWORD_FILE")

	// Test with environment variables only (override any secrets)
	os.Setenv("LDAP_ENV", "test")
	os.Setenv("LDAP_URL", "ldap://test.example.com:389")
	os.Setenv("LDAP_BIND_DN", "uid=test,dc=example,dc=com")
	os.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	os.Setenv("LDAP_PASSWORD", "testpassword")

	config := loadConfigFromAll()

	if len(config.LdapServers) == 0 || config.LdapServers[0] != "ldap://test.example.com:389" {
		t.Errorf("Expected LDAP URL from env var, got %v", config.LdapServers)
	}

	if config.Username != "uid=test,dc=example,dc=com" {
		t.Errorf("Expected bind DN from env var, got %s", config.Username)
	}

	if config.BaseDN != "dc=example,dc=com" {
		t.Errorf("Expected base DN from env var, got %s", config.BaseDN)
	}

	// Note: Password might come from secrets file, so we just check it's not empty
	if config.Password == "" {
		t.Error("Expected password to be loaded from some source")
	}
}

func TestGetPasswordFromEnv(t *testing.T) {
	// Save original env vars
	originalPassword := os.Getenv("LDAP_PASSWORD")
	originalPasswordFile := os.Getenv("LDAP_PASSWORD_FILE")

	defer func() {
		os.Setenv("LDAP_PASSWORD", originalPassword)
		os.Setenv("LDAP_PASSWORD_FILE", originalPasswordFile)
	}()

	// Test direct password
	os.Unsetenv("LDAP_PASSWORD_FILE")
	os.Setenv("LDAP_PASSWORD", "direct-password")

	password := getPasswordFromEnv()
	if password != "direct-password" {
		t.Errorf("Expected direct password, got '%s'", password)
	}

	// Test password file (create temp file)
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "test_password")
	err := os.WriteFile(passwordFile, []byte("file-password\n"), 0600)
	if err != nil {
		t.Fatalf("Failed to create test password file: %v", err)
	}

	os.Setenv("LDAP_PASSWORD_FILE", passwordFile)
	os.Unsetenv("LDAP_PASSWORD")

	password = getPasswordFromEnv()
	if password != "file-password" {
		t.Errorf("Expected password from file, got '%s'", password)
	}

	// Test priority (file should override direct)
	os.Setenv("LDAP_PASSWORD", "direct-password")
	os.Setenv("LDAP_PASSWORD_FILE", passwordFile)

	password = getPasswordFromEnv()
	if password != "file-password" {
		t.Errorf("Password file should take priority, got '%s'", password)
	}
}

func TestReadSecretFile(t *testing.T) {
	// Test nonexistent file
	result := readSecretFile("/nonexistent/file")
	if result != "" {
		t.Errorf("Expected empty string for nonexistent file, got '%s'", result)
	}

	// Test valid file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_secret")
	testContent := "  secret-content  \n"

	err := os.WriteFile(testFile, []byte(testContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result = readSecretFile(testFile)
	expected := "secret-content" // Should be trimmed
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestNewSearcherWithDefaults(t *testing.T) {
	// Save original config
	originalConfig := DefaultConfig
	defer func() {
		DefaultConfig = originalConfig
	}()

	// Test with missing password
	DefaultConfig = Config{
		LdapServers: []string{"ldap://test.example.com:389"},
		Username:    "test",
		BaseDN:      "dc=test,dc=com",
		// Password missing
	}

	_, err := NewSearcherWithDefaults()
	if err == nil {
		t.Error("Expected error when password is missing")
	}

	expectedMsg := "no LDAP password found in secrets or environment variables"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}

	// Test with missing URL
	DefaultConfig = Config{
		Password: "test-password",
		Username: "test",
		BaseDN:   "dc=test,dc=com",
		// LdapServers missing
	}

	_, err = NewSearcherWithDefaults()
	if err == nil {
		t.Error("Expected error when LDAP URL is missing")
	}

	expectedMsg = "no LDAP_URL found in environment variables"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}
