package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	ldap_redhat "github.com/openshift-eng/go-ldap-redhat"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ldapcheck <uid_or_email>")
		os.Exit(1)
	}

	uid := os.Args[1]
	ctx := context.Background()

	// Create searcher using default configuration (YAML + env vars)
	s, err := ldap_redhat.NewSearcherWithDefaults()
	if err != nil {
		log.Fatalf("Failed to create searcher: %v", err)
	}
	defer s.Close()

	fmt.Printf("LDAP connection successful! Searching for: %s\n", uid)

	// Determine search type
	var id ldap_redhat.Identifier
	if strings.Contains(uid, "@") {
		id = ldap_redhat.Identifier{Type: ldap_redhat.IDTEmail, Value: uid}
		fmt.Printf("Searching by email: %s\n", uid)
	} else {
		id = ldap_redhat.Identifier{Type: ldap_redhat.IDTUID, Value: uid}
		fmt.Printf("Searching by UID: %s\n", uid)
	}

	// Search by UID or email
	user, err := s.GetUser(ctx, id)
	if err != nil {
		log.Fatalf("User lookup failed: %v", err)
	}

	fmt.Printf("Found user: %s (%s)\n", user.UID, user.Email)
	fmt.Printf("Name: %s %s\n", user.DisplayName, user.Surname)
	fmt.Printf("Title: %s\n", user.Title)
	fmt.Printf("Location: %s\n", user.RhatLocation)
	fmt.Printf("Cost Center: %s\n", user.CostCenter)
	if user.RhatTermDate != "" {
		fmt.Printf("  Terminated: %s\n", user.RhatTermDate)
	}
}
