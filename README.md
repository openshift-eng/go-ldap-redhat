# Go LDAP Red Hat

A simple, clean Go library for LDAP authentication and user lookup with Red Hat infrastructure.

## Features

- **Simple API**: Easy-to-use interface for LDAP operations
- **Secure Connections**: Supports both `ldaps://` and `ldap://` with StartTLS
- **Multi-Environment Config**: YAML configuration with local/dev/prod environments
- **Flexible Password Loading**: Secrets folder, password files, or environment variables
- **Red Hat Optimized**: Pre-configured for Red Hat LDAP infrastructure
- **Type Safety**: Strongly typed user records and search identifiers
- **Comprehensive Testing**: 21 tests including real LDAP integration
- **Development Automation**: Professional Makefile with 20+ commands
- **Error Handling**: Enterprise-grade error reporting and validation

## Installation

```bash
go get github.com/openshift-eng/go-ldap-redhat
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    ldap_redhat "github.com/openshift-eng/go-ldap-redhat"
)

func main() {
    // Configure LDAP connection
    config := ldap_redhat.Config{
        LdapServers: []string{"ldap://apps-ldap.corp.redhat.com:389"},
        Username:    "uid=service-account,ou=users,dc=redhat,dc=com",
        Password:    "your-password",
        BaseDN:      "dc=redhat,dc=com",
        UseStartTLS: true,
        VerifySSL:   false, // Internal Red Hat LDAP
    }

    // Create searcher
    searcher, err := ldap_redhat.NewSearcher(config)
    if err != nil {
        log.Fatal(err)
    }
    defer searcher.Close()

    // Search by email
    identifier := ldap_redhat.Identifier{
        Type:  ldap_redhat.IDTEmail,
        Value: "user@redhat.com",
    }

    ctx := context.Background()
    user, err := searcher.GetUser(ctx, identifier)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found: %s (%s)\n", user.UID, user.Email)
    fmt.Printf("Title: %s\n", user.Title)
    fmt.Printf("Location: %s\n", user.RhatLocation)
}
```

## API Reference

### Types

#### Config
```go
type Config struct {
    LdapServers []string  // LDAP server URLs
    Port        int       // Port (usually included in URL)
    Username    string    // Bind DN for authentication
    Password    string    // Service account password
    BaseDN      string    // Base DN for searches
    UseStartTLS bool      // Enable StartTLS
    VerifySSL   bool      // Verify SSL certificates
}
```

#### UserRecord
```go
type UserRecord struct {
    UID            string  // User ID (login name)
    Email          string  // Email address
    DisplayName    string  // Full display name
    Surname        string  // Last name
    Title          string  // Job title
    ManagerUID     string  // Manager's DN
    CostCenter     string  // Cost center code
    CostCenterDesc string  // Cost center description
    RhatLocation   string  // Office/remote location
    RhatJobCode    string  // Red Hat job code
    RhatUUID       string  // Unique Red Hat UUID
    RhatHireDate   string  // Hire date (YYYYMMDDHHMMSSZ)
    RhatTermDate   string  // Termination date (empty if active)
    RhatAdjSvcDate string  // Adjusted service date
}
```

#### Identifier
```go
type Identifier struct {
    Type  int     // IDTUID or IDTEmail
    Value string  // The actual UID or email
}

// Constants
const (
    IDTUID = iota    // Search by UID
    IDTEmail         // Search by email
)
```

### Functions

#### NewSearcher
```go
func NewSearcher(config Config) (*Searcher, error)
```
Creates a new LDAP searcher with the given configuration.

#### GetUser
```go
func (s *Searcher) GetUser(ctx context.Context, id Identifier) (UserRecord, error)
```
Searches for a user by UID or email address.

#### Close
```go
func (s *Searcher) Close() error
```
Closes the LDAP connection.

## Usage Examples

### Search by UID
```go
identifier := ldap_redhat.Identifier{
    Type:  ldap_redhat.IDTUID,
    Value: "johndoe",
}
user, err := searcher.GetUser(ctx, identifier)
```

### Search by Email
```go
identifier := ldap_redhat.Identifier{
    Type:  ldap_redhat.IDTEmail,
    Value: "johndoe@redhat.com",
}
user, err := searcher.GetUser(ctx, identifier)
```

### Red Hat LDAP Configuration
```go
config := ldap_redhat.Config{
    LdapServers: []string{"ldap://apps-ldap.corp.redhat.com:389"},
    Username:    "uid=pco-deleted-users-query,ou=users,dc=redhat,dc=com",
    Password:    "service-account-password",
    BaseDN:      "dc=redhat,dc=com",
    UseStartTLS: true,
    VerifySSL:   false,
}
```

## CLI Tool

The library includes a command-line tool for testing:

```bash
# Build the CLI
go build ./cmd/ldapcheck

# Set environment variables
export LDAP_URL="ldap://apps-ldap.corp.redhat.com:389"
export LDAP_BIND_DN="uid=pco-deleted-users-query,ou=users,dc=redhat,dc=com"
export LDAP_PASSWORD="your-password"
export LDAP_BASE_DN="dc=redhat,dc=com"
export LDAP_START_TLS="true"

# Search for a user
./ldapcheck johndoe@redhat.com
```

## Error Handling

The library returns descriptive errors for common issues:

- **Connection failures**: Network or server issues
- **Authentication failures**: Invalid credentials
- **User not found**: No matching user in LDAP
- **Invalid identifier types**: Unknown search type

## Security Considerations

- **Service Accounts**: Use dedicated service accounts with minimal permissions
- **TLS**: Always use StartTLS or LDAPS for production
- **Password Management**: Store passwords securely, never in code
- **Connection Pooling**: Close connections when done to free resources

## Contributing

This library is designed for Red Hat's internal LDAP infrastructure. For issues or improvements, please contact the maintainers.

## License

Apache License 2.0 - see LICENSE file for details.

## Development

### Building and Testing

```bash
# Install dependencies
make install

# Run all tests
make test

# Build library and CLI
make build
make cli

# Run CLI tool
make run-cli USER=jemedina@redhat.com

# Check release readiness
make release-check
```

### Available Make Commands

Run `make help` to see all available commands including:
- Build automation (`make build`, `make cli`)
- Testing (`make test`, `make benchmark`, `make coverage`)
- Code quality (`make fmt`, `make vet`, `make check`)
- Development workflow (`make dev`, `make quick`)

## Changelog

### v1.1.0
- Add comprehensive test suite (21 tests)
- Add LDAP_PASSWORD_FILE environment variable support
- Add YAML password_file configuration for multi-environment
- Add professional Makefile with development automation
- Add enterprise-appropriate clean output (no emojis)
- Fix deprecated io/ioutil usage
- Improve variable naming (LDAP_START_TLS)
- Add .gitignore and development infrastructure

### v1.0.0
- Initial release
- Basic LDAP search functionality
- Red Hat LDAP optimization
- CLI tool included
