// Command aivault is the single static binary containing both the gateway
// server and the management CLI (SPEC 1).
package main

import "github.com/ZN9-KYANT/aivault/internal/cli"

func main() {
	cli.Execute()
}
