// Command aclplan prints the setfacl commands `paneldns-agent enrol`
// would run for a config file, without enrolling. CI uses it to set up
// the ACL-only access test; an administrator can use it to review or
// re-apply the ACLs after a panel reset them.
//
//	aclplan /etc/paneldns-agent.conf | sh
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

func main() {
	path := config.DefaultPath
	if len(os.Args) == 2 {
		path = os.Args[1]
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aclplan:", err)
		os.Exit(1)
	}
	plan, err := enrol.PlanACLs(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aclplan:", err)
		os.Exit(1)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	for _, s := range plan.Skipped {
		fmt.Fprintln(os.Stderr, "skipped (key material):", s)
	}
	for _, c := range plan.Commands() {
		q := make([]string, len(c))
		for i, a := range c {
			q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		fmt.Println(strings.Join(q, " "))
	}
}
