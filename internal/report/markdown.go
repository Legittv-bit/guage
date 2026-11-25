package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/posture-sec/guage/internal/model"
	"github.com/posture-sec/guage/internal/sanitize"
)

// Markdown writes the report as a Markdown document, for a review comment, an
// issue body or a scheduled job's summary.
//
// Every value that came from the chain, a policy file or a stellar.toml is escaped
// with sanitize.Markdown before it reaches the page, so a home domain or an
// account name cannot start markup of its own. Finding evidence is emitted only
// inside a fence longer than any backtick run it contains, which is the same rule
// the sanitizer applies to every other fenced block in this tree.
//
// The document carries the same facts and findings as the text report, in the same
// order, so an operator who reads one can follow the other. It is not a second
// report: severity, wording, fingerprints, ordering and the limits footer all come
// from the same prepared copy.
func Markdown(w io.Writer, r model.Report) error {
	prepared := prepare(r)
	var b strings.Builder

	fmt.Fprintf(&b, "# Gauge %s\n\n", md(prepared.ToolVersion))
	fmt.Fprintf(&b, "network: %s\n\n", md(prepared.Network))
	fmt.Fprintf(&b, "ledger: %d\n\n", prepared.Ledger)

	if len(prepared.Accounts) == 0 {
		b.WriteString("no accounts were checked\n\n")
	}
	for _, ar := range prepared.Accounts {
		writeMarkdownAccount(&b, ar)
	}

	high, warn, info, accepted := countFindings(prepared)
	fmt.Fprintf(&b, "**result:** %d findings (%d high, %d warn, %d info), %d accepted\n\n",
		high+warn+info, high, warn, info, accepted)
	fmt.Fprintf(&b, "**exit code:** %d\n\n", prepared.ExitCode)
	fmt.Fprintf(&b, "---\n\nlimits: %s\n", md(Limits))

	_, err := io.WriteString(w, b.String())
	return err
}

func writeMarkdownAccount(b *strings.Builder, ar model.AccountReport) {
	s := ar.Snapshot
	fmt.Fprintf(b, "## account %s\n\n", md(s.ID))
	fmt.Fprintf(b, "- endpoint: %s\n", md(emptyAs(s.Endpoint, "(none)")))
	switch {
	case ar.Missing:
		b.WriteString("- not found on this endpoint (never created, or merged)\n")
	case ar.Skipped != "":
		fmt.Fprintf(b, "- no state read: %s\n", md(ar.Skipped))
	default:
		fmt.Fprintf(b, "- as of ledger %d, sequence %s\n", s.Ledger, md(emptyAs(s.Sequence, "(none)")))
		fmt.Fprintf(b, "- thresholds: low %d, medium %d, high %d\n",
			s.Thresholds.Low, s.Thresholds.Medium, s.Thresholds.High)
		if reachability := markdownReachability(ar.Facts); reachability != "" {
			fmt.Fprintf(b, "- minimum signers to authorize: %s\n", reachability)
		}
		fmt.Fprintf(b, "- flags: auth_required=%t auth_revocable=%t auth_immutable=%t clawback=%t\n",
			s.Flags.AuthRequired, s.Flags.AuthRevocable, s.Flags.AuthImmutable, s.Flags.ClawbackEnabled)
		fmt.Fprintf(b, "- home domain: %s\n", md(describedDomain(s.HomeDomain)))
		fmt.Fprintf(b, "- sponsor: %s\n", md(emptyAs(s.Sponsor, "(none)")))
		fmt.Fprintf(b, "- signers: %d\n", len(s.Signers))
		for _, signer := range s.Signers {
			fmt.Fprintf(b, "  - %s %s weight %d", md(signer.Key), md(string(signer.Type)), signer.Weight)
			if signer.Sponsor != "" {
				fmt.Fprintf(b, " sponsored by %s", md(signer.Sponsor))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")

	writeMarkdownDeclared(b, ar.Facts)
	writeMarkdownIdentity(b, ar.Facts, s)
	writeMarkdownFindings(b, ar.Findings)
}

// markdownReachability is the text renderer's line without the writer, so the two
// formats cannot disagree about which tiers an account's own weights can reach.
func markdownReachability(facts *model.AccountFacts) string {
	if facts == nil || facts.Reachability == nil {
		return ""
	}
	r := facts.Reachability
	return fmt.Sprintf("low %s, medium %s, high %s",
		minimumText(r.Low), minimumText(r.Medium), minimumText(r.High))
}

func writeMarkdownDeclared(b *strings.Builder, facts *model.AccountFacts) {
	if facts == nil {
		return
	}
	b.WriteString("### declared\n\n")
	declared := facts.Declared
	if declared == nil {
		b.WriteString("- nothing; this run read no policy file, so only the universal rules ran\n\n")
		return
	}
	header := "- role: " + md(declared.Role)
	if name := declared.Name; name != "" {
		header += ", name " + md(strconv.Quote(name))
	}
	b.WriteString(header + "\n")

	fmt.Fprintf(b, "- expected_signers: %s\n", signersText(declared.ExpectedSigners))
	fmt.Fprintf(b, "- expected_thresholds: %s\n", thresholdsText(declared.ExpectedThresholds))
	fmt.Fprintf(b, "- expected_flags: %s\n", flagsText(declared.ExpectedFlags))
	fmt.Fprintf(b, "- home_domain: %s\n", mdQuoted(declared.HomeDomain, notDeclared))
	if declared.ExpectLocked == nil {
		fmt.Fprintf(b, "- expect_locked: %s\n\n", notDeclared)
		return
	}
	if declared.ExpectLockedIgnored {
		fmt.Fprintf(b, "- expect_locked: %t, which role %s is not allowed to declare; it is read for issuer alone\n\n",
			*declared.ExpectLocked, md(strconv.Quote(declared.Role)))
		return
	}
	fmt.Fprintf(b, "- expect_locked: %t\n\n", *declared.ExpectLocked)
}

// writeMarkdownIdentity prints what the guarded fetcher observed under a heading of
// its own. An account with no domain, or whose domain was never fetched, gets the
// same sentence the text report uses rather than an empty section.
func writeMarkdownIdentity(b *strings.Builder, facts *model.AccountFacts, s model.AccountSnapshot) {
	if facts == nil {
		return
	}
	identity := facts.Identity
	if identity == nil {
		if !s.HasHomeDomain() {
			return
		}
		b.WriteString("### identity document\n\n")
		b.WriteString("- never fetched, so the published home domain is unverified\n\n")
		return
	}

	b.WriteString("### identity document\n\n")
	if identity.Reachable {
		fmt.Fprintf(b, "- %s served a readable file\n", md(identity.HomeDomain))
	} else {
		fmt.Fprintf(b, "- %s did not serve a readable file\n", md(identity.HomeDomain))
	}
	fmt.Fprintf(b, "- step: %s\n", md(identity.Step))
	if identity.Detail != "" {
		fmt.Fprintf(b, "- detail: %s\n", md(identity.Detail))
	}
	if identity.Status == 0 {
		b.WriteString("- fetch: no response received\n")
	} else {
		cors := "absent"
		if identity.CORSPresent {
			cors = "present"
		}
		fmt.Fprintf(b, "- fetch: status %d, %d redirect hops, %d bytes, CORS %s\n",
			identity.Status, identity.Hops, identity.Bytes, cors)
	}
	if !identity.Reachable {
		b.WriteString("\n")
		return
	}

	network := mdQuoted(identity.NetworkPassphrase, notNamed)
	if matches := identity.NetworkMatches; matches != nil {
		agreement := " (not this network)"
		if *matches {
			agreement = " (this network)"
		}
		network += agreement
	}
	fmt.Fprintf(b, "- network_passphrase: %s\n", network)
	fmt.Fprintf(b, "- signing_key: %s\n", mdQuoted(identity.SigningKey, notNamed))
	fmt.Fprintf(b, "- horizon_url: %s\n", mdQuoted(identity.HorizonURL, notNamed))
	fmt.Fprintf(b, "- version: %s\n", mdQuoted(identity.Version, notNamed))
	if malformed := identity.MalformedAccounts; malformed > 0 {
		fmt.Fprintf(b, "- accounts: %d listed, %d rejected as not an address\n",
			len(identity.Accounts), malformed)
	} else {
		fmt.Fprintf(b, "- accounts: %d listed\n", len(identity.Accounts))
	}
	b.WriteString("\n")
}

func writeMarkdownFindings(b *strings.Builder, findings []model.Finding) {
	b.WriteString("### findings\n\n")
	if len(findings) == 0 {
		b.WriteString("none\n\n")
		return
	}
	for _, f := range findings {
		accepted := ""
		if f.Accepted {
			accepted = " (accepted)"
		}
		fmt.Fprintf(b, "#### %s `%s`%s\n\n", strings.ToUpper(f.Severity.String()), md(f.RuleID), accepted)
		fmt.Fprintf(b, "%s\n\n", md(f.Message))
		if f.Evidence != "" {
			b.WriteString(sanitize.Fenced(f.Evidence))
			b.WriteString("\n\n")
		}
		fmt.Fprintf(b, "fingerprint: %s\n\n", md(f.Fingerprint))
	}
}

// md is sanitize.Markdown under a short name, so every interpolation in this file
// visibly goes through the escaper rather than looking like ordinary text.
func md(s string) string { return sanitize.Markdown(s) }

// mdQuoted prints a value a policy or a document supplied the way the text report
// does, with Go quoting and then markdown escaping. An absent pointer is not the
// same as an empty string, so the reason it is missing is printed instead.
func mdQuoted(value *string, whenMissing string) string {
	if value == nil {
		return whenMissing
	}
	return md(strconv.Quote(*value))
}
