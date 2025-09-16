package ldap_redhat

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"
)

// Version of the go-ldap-redhat library
const Version = "v1.2.0"

// Config holds LDAP connection configuration
type Config struct {
	LdapServers []string
	Port        int
	Username    string
	Password    string
	BaseDN      string
	UseStartTLS bool
	VerifySSL   bool
}

// YAMLConfig represents the YAML configuration structure
type YAMLConfig struct {
	Environments map[string]EnvConfig `yaml:"environments"`
}

type EnvConfig struct {
	LdapServers  []string `yaml:"ldap_servers"`
	Username     string   `yaml:"username"`
	BaseDN       string   `yaml:"base_dn"`
	UseStartTLS  bool     `yaml:"use_start_tls"`
	VerifySSL    bool     `yaml:"verify_ssl"`
	PasswordFile string   `yaml:"password_file"`
}

// DefaultConfig holds the auto-loaded configuration
var DefaultConfig Config

func init() {
	DefaultConfig = loadConfigFromAll()
}

type Searcher struct {
	config Config
	conn   *ldap.Conn
}

type UserRecord struct {
	UID            string
	Email          string
	DisplayName    string
	Surname        string
	Title          string
	ManagerUID     string
	CostCenter     string
	CostCenterDesc string
	RhatLocation   string
	RhatJobCode    string
	RhatUUID       string
	RhatHireDate   string
	RhatTermDate   string
	RhatAdjSvcDate string
}

type Identifier struct {
	Type  int
	Value string
}

// Constants for identifier types
const (
	IDTUID = iota
	IDTEmail
)

// NewSearcherFromEnv creates a searcher using environment variables
func NewSearcherFromEnv() (*Searcher, error) {
	config := Config{
		LdapServers: []string{os.Getenv("LDAP_URL")},
		Username:    os.Getenv("LDAP_BIND_DN"),
		Password:    getPasswordFromEnv(),
		BaseDN:      os.Getenv("LDAP_BASE_DN"),
		UseStartTLS: os.Getenv("LDAP_START_TLS") == "true",
		VerifySSL:   os.Getenv("LDAP_VERIFY_SSL") != "false",
	}
	return NewSearcher(config)
}

// NewSearcher creates a searcher with the given config
func NewSearcher(config Config) (*Searcher, error) {
	searcher := &Searcher{config: config}
	if len(config.LdapServers) == 0 {
		return searcher, nil
	}
	ldapURL := config.LdapServers[0]
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", ldapURL, err)
	}
	if config.UseStartTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
			ServerName:         extractHostname(ldapURL),
		}
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}
	if config.Username != "" && config.Password != "" {
		err = conn.Bind(config.Username, config.Password)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
		}
	}
	searcher.conn = conn
	return searcher, nil
}

func (s *Searcher) Close() error {
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

func (s *Searcher) GetUser(ctx context.Context, id Identifier) (UserRecord, error) {
	if s.conn == nil {
		return UserRecord{}, fmt.Errorf("LDAP connection not established")
	}
	var filter string
	switch id.Type {
	case IDTUID:
		filter = fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(id.Value))
	case IDTEmail:
		filter = fmt.Sprintf("(mail=%s)", ldap.EscapeFilter(id.Value))
	default:
		return UserRecord{}, fmt.Errorf("unknown identifier type: %d", id.Type)
	}
	searchRequest := ldap.NewSearchRequest(
		"ou=users,dc=redhat,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"uid", "mail", "cn", "sn", "title", "manager", "rhatCostCenter", "rhatLocation", "rhatJobCode", "rhatUUID", "rhatHireDate", "rhatTermDate"},
		nil,
	)
	result, err := s.conn.Search(searchRequest)
	if err != nil {
		return UserRecord{}, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return UserRecord{}, fmt.Errorf("user not found in LDAP directory: %s", id.Value)
	}
	entry := result.Entries[0]
	user := UserRecord{
		UID:          entry.GetAttributeValue("uid"),
		Email:        entry.GetAttributeValue("mail"),
		DisplayName:  entry.GetAttributeValue("cn"),
		Surname:      entry.GetAttributeValue("sn"),
		Title:        entry.GetAttributeValue("title"),
		ManagerUID:   entry.GetAttributeValue("manager"),
		CostCenter:   entry.GetAttributeValue("rhatCostCenter"),
		RhatLocation: entry.GetAttributeValue("rhatLocation"),
		RhatJobCode:  entry.GetAttributeValue("rhatJobCode"),
		RhatUUID:     entry.GetAttributeValue("rhatUUID"),
		RhatHireDate: entry.GetAttributeValue("rhatHireDate"),
		RhatTermDate: entry.GetAttributeValue("rhatTermDate"),
	}
	return user, nil
}

// loadConfigFromAll loads configuration: YAML → env vars → defaults
func loadConfigFromAll() Config {
	config := Config{}

	// 1. Start with YAML config
	if yamlConfig := loadYAMLConfig(); yamlConfig != nil {
		config = *yamlConfig
	}

	// 2. Fill empty fields from environment variables
	if len(config.LdapServers) == 0 {
		if url := os.Getenv("LDAP_URL"); url != "" {
			config.LdapServers = []string{url}
		}
	}

	if config.Username == "" {
		if bindDN := os.Getenv("LDAP_BIND_DN"); bindDN != "" {
			config.Username = bindDN
		}
	}

	if config.BaseDN == "" {
		if baseDN := os.Getenv("LDAP_BASE_DN"); baseDN != "" {
			config.BaseDN = baseDN
		}
	}

	// Password: YAML password_file → LDAP_PASSWORD_FILE → LDAP_PASSWORD → error
	if config.Password == "" {
		if passwordFile := os.Getenv("LDAP_PASSWORD_FILE"); passwordFile != "" {
			if password := readSecretFile(passwordFile); password != "" {
				config.Password = password
			}
		}
		if config.Password == "" {
			if password := os.Getenv("LDAP_PASSWORD"); password != "" {
				config.Password = password
			}
		}
	}

	// 3. Set defaults for boolean flags if not set in YAML
	if os.Getenv("LDAP_START_TLS") != "" {
		config.UseStartTLS = os.Getenv("LDAP_START_TLS") == "true"
	}

	if os.Getenv("LDAP_VERIFY_SSL") != "" {
		config.VerifySSL = os.Getenv("LDAP_VERIFY_SSL") == "true"
	}

	return config
}

// loadYAMLConfig loads configuration from YAML file
func loadYAMLConfig() *Config {
	env := getEnvironment()

	// Try multiple config file locations
	configPaths := []string{
		"config.yaml",
		"configs/config.yaml",
		filepath.Join(os.Getenv("HOME"), ".config", "ldap", "config.yaml"),
	}

	for _, configPath := range configPaths {
		if config := tryLoadYAMLFile(configPath, env); config != nil {
			return config
		}
	}

	return nil
}

// tryLoadYAMLFile attempts to load and parse a YAML config file
func tryLoadYAMLFile(configPath, env string) *Config {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	var yamlConfig YAMLConfig
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil
	}

	envConfig, exists := yamlConfig.Environments[env]
	if !exists {
		return nil
	}

	config := &Config{
		LdapServers: envConfig.LdapServers,
		Username:    envConfig.Username,
		BaseDN:      envConfig.BaseDN,
		UseStartTLS: envConfig.UseStartTLS,
		VerifySSL:   envConfig.VerifySSL,
	}

	// Load password from YAML-specified file if configured
	if envConfig.PasswordFile != "" {
		// Expand ~ to home directory
		passwordPath := envConfig.PasswordFile
		if strings.HasPrefix(passwordPath, "~/") {
			homeDir, _ := os.UserHomeDir()
			passwordPath = filepath.Join(homeDir, passwordPath[2:])
		}
		if password := readSecretFile(passwordPath); password != "" {
			config.Password = password
		}
	}

	return config
}

// getEnvironment returns the current environment (local, dev, prod)
func getEnvironment() string {
	if env := os.Getenv("LDAP_ENV"); env != "" {
		return env
	}
	if env := os.Getenv("ENV"); env != "" {
		return env
	}
	return "local" // default
}

// readSecretFile safely reads a secret file and returns its contents
func readSecretFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// NewSearcherWithDefaults creates a searcher using the auto-loaded default config
func NewSearcherWithDefaults() (*Searcher, error) {
	if DefaultConfig.Password == "" {
		return nil, fmt.Errorf("no LDAP password found in secrets or environment variables")
	}
	if len(DefaultConfig.LdapServers) == 0 {
		return nil, fmt.Errorf("no LDAP_URL found in environment variables")
	}
	return NewSearcher(DefaultConfig)
}

// getPasswordFromEnv loads password from LDAP_PASSWORD_FILE or LDAP_PASSWORD
func getPasswordFromEnv() string {
	// Try LDAP_PASSWORD_FILE first
	if passwordFile := os.Getenv("LDAP_PASSWORD_FILE"); passwordFile != "" {
		if password := readSecretFile(passwordFile); password != "" {
			return password
		}
	}
	// Fallback to direct LDAP_PASSWORD
	return os.Getenv("LDAP_PASSWORD")
}

// extractHostname extracts hostname from LDAP URL for TLS ServerName
func extractHostname(ldapURL string) string {
	// Remove protocol prefix
	url := strings.TrimPrefix(ldapURL, "ldap://")
	url = strings.TrimPrefix(url, "ldaps://")

	// Remove port if present
	if colonIndex := strings.Index(url, ":"); colonIndex != -1 {
		url = url[:colonIndex]
	}

	return url
}
