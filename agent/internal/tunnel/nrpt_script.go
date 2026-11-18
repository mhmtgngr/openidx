package tunnel

import (
	"fmt"
	"regexp"
	"strings"
)

// The PowerShell the agent runs to point Windows' name resolution policy table
// (NRPT) at its own resolver. It is built here, with no build tag, so it can be
// read and tested on every platform; only nrpt_windows.go runs it.
//
// Every name that reaches a script passes nameRE first: lower-case letters,
// digits and hyphens in dot-separated labels, at least two labels. No quote,
// semicolon, space or wildcard can be in a name, so a name from the server can
// never become PowerShell.

const (
	// nrptMine marks the rules the agent writes, so it removes only its own.
	nrptMine = "Added by openidx-agent"
	// nrptTheirs is the comment ziti-edge-tunnel puts on its rules
	// ("Added by <id>", windows-scripts.c); the agent replaces those for the
	// names it answers itself, and puts them back when it stops.
	nrptTheirs = "Added by openidx.ziti-edge-tunnel"
	// nrptTheirsDisplay is the prefix of the display name the tunneler gives.
	nrptTheirsDisplay = "openidx.ziti-edge-tunnel:"
)

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// scriptNames checks every name and joins them for a single-quoted PowerShell
// string that the script splits on commas.
func scriptNames(names []string) (string, error) {
	for _, n := range names {
		if len(n) > maxDNSName || !nameRE.MatchString(n) {
			return "", fmt.Errorf("%q is not a name the agent will put in a script", n)
		}
	}
	return strings.Join(names, ","), nil
}

// nrptApplyScript makes the NRPT send exactly names to server, among the rules
// the agent owns: it removes the tunneler's rule for each of those names, removes
// an agent rule that is no longer wanted or points elsewhere, adds the missing
// ones, and flushes the resolver cache if anything changed (a name that was
// answered "no such name" a moment ago must not be remembered).
func nrptApplyScript(names []string, server string) (string, error) {
	joined, err := scriptNames(names)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
$server='%s'; $mine='%s'; $theirs='%s'
$want=@('%s'.Split(',') | Where-Object { $_ })
$changed=$false
foreach($r in @(Get-DnsClientNrptRule)){
  $ns=@($r.Namespace)
  if($r.Comment -eq $theirs -and @($ns | Where-Object { $want -contains $_ }).Count -gt 0){ Remove-DnsClientNrptRule -Name $r.Name -Force; $changed=$true; continue }
  if($r.Comment -eq $mine){
    $keep = ($ns.Count -eq 1) -and ($want -contains $ns[0]) -and ((@($r.NameServers) -join ',') -eq $server)
    if(-not $keep){ Remove-DnsClientNrptRule -Name $r.Name -Force; $changed=$true }
  }
}
$have=@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $mine } | ForEach-Object { @($_.Namespace)[0] })
foreach($n in $want){
  if($have -notcontains $n){ Add-DnsClientNrptRule -Namespace $n -NameServers $server -Comment $mine -DisplayName ('openidx-agent:'+$n); $changed=$true }
}
if($changed){ Clear-DnsClientCache }
`, server, nrptMine, nrptTheirs, joined), nil
}

// nrptClearScript removes every rule the agent wrote and, for each name in
// restore that no rule covers now, writes the rule the tunneler would have
// written (the tunnel is still up and will manage it from there).
func nrptClearScript(restore []string, tunnelerServer string) (string, error) {
	joined, err := scriptNames(restore)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
$mine='%s'; $theirs='%s'; $display='%s'; $tunnelerDns='%s'
$restore=@('%s'.Split(',') | Where-Object { $_ })
$changed=$false
foreach($r in @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $mine })){ Remove-DnsClientNrptRule -Name $r.Name -Force; $changed=$true }
$covered=@(Get-DnsClientNrptRule | ForEach-Object { @($_.Namespace) })
foreach($n in $restore){
  if($covered -notcontains $n){ Add-DnsClientNrptRule -Namespace $n -NameServers $tunnelerDns -Comment $theirs -DisplayName ($display+$n); $changed=$true }
}
if($changed){ Clear-DnsClientCache }
`, nrptMine, nrptTheirs, nrptTheirsDisplay, tunnelerServer, joined), nil
}
