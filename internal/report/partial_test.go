package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/posture-sec/guage/internal/model"
)

func TestMixedAccountOutcomes(t *testing.T) {
	t.Parallel()
	const skippedID = "GDF6B4EQSNXLTSN4QROIVYLIKDFGUOZLCAGGWSGFAKPY7US72Y4A2IRJ"
	const skippedReason = "the endpoint is on a different network"
	ids := []string{accountOne, accountTwo, skippedID}
	r := model.Report{
		ToolVersion: "0.0.0-test",
		Network:     "Test SDF Network ; September 2015",
		Ledger:      1,
		Accounts: []model.AccountReport{
			{
				Snapshot: model.AccountSnapshot{
					ID:       accountOne,
					Network:  "Test SDF Network ; September 2015",
					Endpoint: "https://horizon-testnet.stellar.org",
					Ledger:   1,
					Sequence: "7",
					Signers:  []model.Signer{},
				},
			},
			{
				Snapshot: model.AccountSnapshot{
					ID:       accountTwo,
					Network:  "Test SDF Network ; September 2015",
					Endpoint: "https://horizon-testnet.stellar.org",
					Ledger:   1,
				},
				Missing: true,
			},
			{
				Snapshot: model.AccountSnapshot{
					ID:       skippedID,
					Network:  "Test SDF Network ; September 2015",
					Endpoint: "https://horizon-testnet.stellar.org",
					Ledger:   1,
				},
				Skipped: skippedReason,
			},
		},
		ExitCode: model.ExitFindings,
	}

	var text bytes.Buffer
	if err := Text(&text, r); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	for _, id := range ids {
		if !strings.Contains(out, id) {
			t.Errorf("text output has no snapshot ID %s:\n%s", id, out)
		}
	}
	for _, want := range []string{
		"not found on this endpoint (never created, or merged)",
		"no state read: " + skippedReason,
		"thresholds: low 0, medium 0, high 0",
		"signers: 0",
		fmt.Sprintf("exit code: %d", r.ExitCode),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output has no %q:\n%s", want, out)
		}
	}
	for _, check := range []struct {
		phrase string
		want   int
	}{
		{"not found on this endpoint", 1},
		{"no state read:", 1},
		{"limits:", 1},
	} {
		if got := strings.Count(out, check.phrase); got != check.want {
			t.Errorf("text output has %d %q lines, want %d:\n%s", got, check.phrase, check.want, out)
		}
	}

	var document bytes.Buffer
	if err := JSON(&document, r); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Accounts []map[string]json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(document.Bytes(), &payload); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, document.String())
	}
	if len(payload.Accounts) != len(ids) {
		t.Fatalf("got %d JSON accounts, want %d", len(payload.Accounts), len(ids))
	}
	for i, id := range ids {
		var snapshot struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(payload.Accounts[i]["snapshot"], &snapshot); err != nil {
			t.Fatalf("account %d has no snapshot ID: %v", i, err)
		}
		if snapshot.ID != id {
			t.Errorf("account %d ID is %q, want %q", i, snapshot.ID, id)
		}
	}
	if _, ok := payload.Accounts[0]["missing"]; ok {
		t.Error("normal account carries missing=true")
	}
	if _, ok := payload.Accounts[0]["skipped"]; ok {
		t.Error("normal account carries a skipped reason")
	}
	var missing bool
	if err := json.Unmarshal(payload.Accounts[1]["missing"], &missing); err != nil || !missing {
		t.Fatalf("missing account flag is %v, error %v", missing, err)
	}
	if _, ok := payload.Accounts[1]["skipped"]; ok {
		t.Error("missing account carries a skipped reason")
	}
	var skipped string
	if err := json.Unmarshal(payload.Accounts[2]["skipped"], &skipped); err != nil || skipped != skippedReason {
		t.Fatalf("skipped reason is %q, error %v", skipped, err)
	}
	if _, ok := payload.Accounts[2]["missing"]; ok {
		t.Error("skipped account carries missing=true")
	}
}
