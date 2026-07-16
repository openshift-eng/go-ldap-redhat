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
const Version = "v1.3.0"

// Config holds LDAP connection configuration
type Config struct {
	LdapServers   []string
	Port          int
	Username      string
	Password      string
	BaseDN        string
	UseStartTLS   bool
	VerifySSL     bool
	TLSServerName string // Optional: Override ServerName for TLS verification (useful when connecting via IP)
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
	DefaultConfig = LoadConfigFromAll()
}

type Searcher struct {
	Config Config
	Conn   *ldap.Conn
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
	Country        string // co — ISO 3166 country code (e.g. "US", "DEU")
	Department     string // ou — organizational unit / department
}

// userAttributes is the canonical list of LDAP attributes fetched for user lookups.
var userAttributes = []string{
	"uid", "mail", "cn", "sn", "title", "manager",
	"rhatCostCenter", "rhatCostCenterDesc", "rhatLocation",
	"rhatJobCode", "rhatUUID", "rhatHireDate", "rhatTermDate", "rhatAdjSvcDate",
	"co", "ou",
}

// entryToUserRecord converts an LDAP entry to a UserRecord.
func entryToUserRecord(entry *ldap.Entry) UserRecord {
	return UserRecord{
		UID:            entry.GetAttributeValue("uid"),
		Email:          entry.GetAttributeValue("mail"),
		DisplayName:    entry.GetAttributeValue("cn"),
		Surname:        entry.GetAttributeValue("sn"),
		Title:          entry.GetAttributeValue("title"),
		ManagerUID:     entry.GetAttributeValue("manager"),
		CostCenter:     entry.GetAttributeValue("rhatCostCenter"),
		CostCenterDesc: entry.GetAttributeValue("rhatCostCenterDesc"),
		RhatLocation:   entry.GetAttributeValue("rhatLocation"),
		RhatJobCode:    entry.GetAttributeValue("rhatJobCode"),
		RhatUUID:       entry.GetAttributeValue("rhatUUID"),
		RhatHireDate:   entry.GetAttributeValue("rhatHireDate"),
		RhatTermDate:   entry.GetAttributeValue("rhatTermDate"),
		RhatAdjSvcDate: entry.GetAttributeValue("rhatAdjSvcDate"),
		Country:        entry.GetAttributeValue("co"),
		Department:     entry.GetAttributeValue("ou"),
	}
}

// ReportSearchOptions configures FindDirectReports behavior.
type ReportSearchOptions struct {
	ExcludeCountries []string // ISO country codes to exclude (e.g. Works Council: "esp","fra","deu")
	Recursive        bool     // walk subtree recursively (default: false = direct reports only)
	MaxDepth         int      // max recursion depth (0 = unlimited, only used if Recursive is true)
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
		Password:    GetPasswordFromEnv(),
		BaseDN:      os.Getenv("LDAP_BASE_DN"),
		UseStartTLS: os.Getenv("LDAP_START_TLS") == "true",
		VerifySSL:   os.Getenv("LDAP_VERIFY_SSL") != "false",
	}
	return NewSearcher(config)
}

// NewSearcher creates a searcher with the given config
func NewSearcher(config Config) (*Searcher, error) {
	searcher := &Searcher{Config: config}
	if len(config.LdapServers) == 0 {
		return searcher, nil
	}
	ldapURL := config.LdapServers[0]
	
	// For ldaps:// URLs, use DialURL with custom TLS config if TLSServerName is set
	var conn *ldap.Conn
	var err error
	if strings.HasPrefix(ldapURL, "ldaps://") && config.TLSServerName != "" {
		serverName := config.TLSServerName
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
			ServerName:         serverName,
		}
		conn, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(ldapURL)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", ldapURL, err)
	}
	if config.UseStartTLS {
		serverName := config.TLSServerName
		if serverName == "" {
			serverName = ExtractHostname(ldapURL)
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
			ServerName:         serverName,
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
	searcher.Conn = conn
	return searcher, nil
}

func (s *Searcher) Close() error {
	if s.Conn != nil {
		s.Conn.Close()
	}
	return nil
}

func (s *Searcher) GetUser(ctx context.Context, id Identifier) (UserRecord, error) {
	if s.Conn == nil {
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
	baseDN := s.Config.BaseDN
	if baseDN == "" {
		baseDN = "ou=users,dc=redhat,dc=com"
	}
	result, err := s.Conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, userAttributes, nil,
	))
	if err != nil {
		return UserRecord{}, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return UserRecord{}, fmt.Errorf("user not found in LDAP directory: %s", id.Value)
	}
	return entryToUserRecord(result.Entries[0]), nil
}

// GetUsers performs a batch lookup of multiple identifiers in a single call.
// Returns results in the same order as the input; missing users have empty UID.
func (s *Searcher) GetUsers(ctx context.Context, ids []Identifier) ([]UserRecord, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if s.Conn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	var parts []string
	for _, id := range ids {
		switch id.Type {
		case IDTUID:
			parts = append(parts, fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(id.Value)))
		case IDTEmail:
			parts = append(parts, fmt.Sprintf("(mail=%s)", ldap.EscapeFilter(id.Value)))
		default:
			return nil, fmt.Errorf("unknown identifier type: %d", id.Type)
		}
	}

	filter := fmt.Sprintf("(|%s)", strings.Join(parts, ""))
	baseDN := s.Config.BaseDN
	if baseDN == "" {
		baseDN = "ou=users,dc=redhat,dc=com"
	}
	result, err := s.Conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, userAttributes, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("LDAP batch search failed: %w", err)
	}

	byUID := map[string]UserRecord{}
	byEmail := map[string]UserRecord{}
	for _, entry := range result.Entries {
		rec := entryToUserRecord(entry)
		byUID[rec.UID] = rec
		if rec.Email != "" {
			byEmail[strings.ToLower(rec.Email)] = rec
		}
	}

	out := make([]UserRecord, len(ids))
	for i, id := range ids {
		switch id.Type {
		case IDTUID:
			out[i] = byUID[id.Value]
		case IDTEmail:
			out[i] = byEmail[strings.ToLower(id.Value)]
		}
	}
	return out, nil
}

// FindDirectReports returns all users whose LDAP manager attribute points to managerUID.
// Use opts to exclude Works Council countries or enable recursive subtree traversal.
func (s *Searcher) FindDirectReports(ctx context.Context, managerUID string, opts ...ReportSearchOptions) ([]UserRecord, error) {
	if s.Conn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	var opt ReportSearchOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	baseDN := s.Config.BaseDN
	if baseDN == "" {
		baseDN = "ou=users,dc=redhat,dc=com"
	}

	reports, err := s.findReportsForUID(ctx, managerUID, baseDN, opt.ExcludeCountries)
	if err != nil {
		return nil, err
	}

	if !opt.Recursive {
		return reports, nil
	}

	return s.walkReports(ctx, reports, baseDN, opt, 1)
}

func (s *Searcher) findReportsForUID(ctx context.Context, managerUID, baseDN string, excludeCountries []string) ([]UserRecord, error) {
	managerDN := fmt.Sprintf("uid=%s,ou=users,dc=redhat,dc=com", ldap.EscapeFilter(managerUID))

	var wcFilter string
	for _, cc := range excludeCountries {
		wcFilter += fmt.Sprintf("(!(co=%s))", strings.TrimSpace(cc))
	}

	filter := fmt.Sprintf("(&(manager=%s)%s)", managerDN, wcFilter)

	result, err := s.Conn.Search(ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, userAttributes, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("LDAP direct reports search failed for %s: %w", managerUID, err)
	}

	var records []UserRecord
	for _, entry := range result.Entries {
		records = append(records, entryToUserRecord(entry))
	}
	return records, nil
}

func (s *Searcher) walkReports(ctx context.Context, current []UserRecord, baseDN string, opt ReportSearchOptions, depth int) ([]UserRecord, error) {
	if opt.MaxDepth > 0 && depth >= opt.MaxDepth {
		return current, nil
	}

	var all []UserRecord
	all = append(all, current...)

	for _, u := range current {
		if u.UID == "" {
			continue
		}
		children, err := s.findReportsForUID(ctx, u.UID, baseDN, opt.ExcludeCountries)
		if err != nil {
			continue
		}
		if len(children) > 0 {
			walked, err := s.walkReports(ctx, children, baseDN, opt, depth+1)
			if err != nil {
				continue
			}
			all = append(all, walked...)
		}
	}
	return all, nil
}

// LoadConfigFromAll loads configuration: YAML → env vars → defaults
func LoadConfigFromAll() Config {
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
			if password := ReadSecretFile(passwordFile); password != "" {
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
	env := GetEnvironment()

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
		if password := ReadSecretFile(passwordPath); password != "" {
			config.Password = password
		}
	}

	return config
}

// getEnvironment returns the current environment (local, dev, prod)
func GetEnvironment() string {
	if env := os.Getenv("LDAP_ENV"); env != "" {
		return env
	}
	if env := os.Getenv("ENV"); env != "" {
		return env
	}
	return "local" // default
}

// ReadSecretFile safely reads a secret file and returns its contents
func ReadSecretFile(path string) string {
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

// GetPasswordFromEnv loads password from LDAP_PASSWORD_FILE or LDAP_PASSWORD
func GetPasswordFromEnv() string {
	// Try LDAP_PASSWORD_FILE first
	if passwordFile := os.Getenv("LDAP_PASSWORD_FILE"); passwordFile != "" {
		if password := ReadSecretFile(passwordFile); password != "" {
			return password
		}
	}
	// Fallback to direct LDAP_PASSWORD
	return os.Getenv("LDAP_PASSWORD")
}

// extractHostname extracts hostname from LDAP URL for TLS ServerName
func ExtractHostname(ldapURL string) string {
	// Remove protocol prefix
	url := strings.TrimPrefix(ldapURL, "ldap://")
	url = strings.TrimPrefix(url, "ldaps://")

	// Remove port if present
	if colonIndex := strings.Index(url, ":"); colonIndex != -1 {
		url = url[:colonIndex]
	}

	return url
}
