// Command admin is the operator CLI: it talks to PostgreSQL directly for
// tasks like registering the first application or force-revoking an admin
// session (spec section 9), rather than being a network listener like
// cmd/server. Subcommands are parsed but not implemented yet -- Milestone 4.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "register-application", "revoke-admin-session":
		fmt.Fprintf(os.Stderr, "%s: not implemented until Milestone 4\n", args[0])
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `manual-approval admin CLI (operator tool, connects to PostgreSQL directly)

Usage:
  admin <command> [flags]

Commands:
  register-application    Register a new protected application (Milestone 4)
  revoke-admin-session    Force-revoke an admin session by issuer/subject (Milestone 4)
`)
}
