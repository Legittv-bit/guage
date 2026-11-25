package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/posture-sec/guage/internal/model"
)

func TestMarkdownGolden(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := Markdown(&buf, sampleReport()); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	checkGolden(t, "sample.markdown.golden", buf.Bytes())
}

// Task 5.3's requirement, in one report: a hostile home domain, account name,
// endpoint and message must not become markup, and the evidence fence must be
// longer than the backtick run inside it so the finding cannot escape its block.
// Evidence reaches the renderer through prepare, which collapses newlines the way
// the text report does, so a hostile line break cannot start a heading either.
func TestMarkdownEscapesChainStrings(t *testing.T) {
	t.Parallel()
	report := model.Report{
		ToolVersion: "0.0.0-test",
		Network:     "*network*",
		Ledger:      7,
		Accounts: []model.AccountReport{{
			Snapshot: model.AccountSnapshot{
				ID:         accountOne,
				Endpoint:   "https://example.com/?a=1&b=2",
				HomeDomain: "<script>alert(1)</script>",
				Sponsor:    "|pipe|",
			},
			Facts: &model.AccountFacts{Declared: &model.DeclaredFacts{
				Role: "other", Name: "[x](y)",
			}},
			Findings: []model.Finding{model.NewFinding("sig-hashx", model.SevWarn, accountOne,
				"*bold* [link](x) `code`", "first ``` run\n# heading")},
		}},
	}

	var buf bytes.Buffer
	if err := Markdown(&buf, report); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()
	for _, raw := range []string{
		"<script>", "[x](y)", "*network*", "|pipe|", "*bold*", "[link](x)", "`code`",
	} {
		if strings.Contains(out, raw) {
			t.Errorf("markdown output kept raw %q:\n%s", raw, out)
		}
	}
	if !strings.Contains(out, "````") {
		t.Fatalf("evidence containing a triple backtick was not fenced with a longer run:\n%s", out)
	}
	// The heading text stays inside the fence, on the one line prepare left it on.
	if !strings.Contains(out, "````\nfirst ``` run # heading\n````") {
		t.Fatalf("evidence did not survive whole inside its fence:\n%s", out)
	}
	if strings.Contains(out, "\n# heading") {
		t.Fatalf("evidence leaked a heading outside its fence:\n%s", out)
	}
}

// The same rule as the sanitizer's own fence test: every backtick run in the body
// is shorter than the fence, whatever the body contains.
func TestMarkdownFenceOutgrowsEveryBacktickRun(t *testing.T) {
	t.Parallel()
	report := model.Report{Accounts: []model.AccountReport{{
		Snapshot: model.AccountSnapshot{ID: accountOne},
		Findings: []model.Finding{model.NewFinding("sig-hashx", model.SevWarn, accountOne, "m",
			"one ` two `` three ``` four ````")},
	}}}
	var buf bytes.Buffer
	if err := Markdown(&buf, report); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "`````") {
		t.Fatalf("the fence is not longer than the longest run in the evidence:\n%s", out)
	}
}

func TestMarkdownIsDeterministic(t *testing.T) {
	t.Parallel()
	var first, second bytes.Buffer
	if err := Markdown(&first, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&second, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("markdown output changed between identical runs")
	}
}

func TestMarkdownEmptyReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := Markdown(&buf, model.Report{ToolVersion: "development"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no accounts were checked") {
		t.Fatalf("empty markdown report = %q", buf.String())
	}
}
