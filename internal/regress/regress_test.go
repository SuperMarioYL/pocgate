package regress

import (
	"context"
	"testing"

	"github.com/SuperMarioYL/pocgate/internal/spec"
)

func TestRunExitCodeParser(t *testing.T) {
	dir := t.TempDir()

	pass, err := Run(context.Background(), dir, "exit 0", spec.ParserExitCode)
	if err != nil {
		t.Fatal(err)
	}
	if pass.ExitCode != 0 || pass.Total != 1 || len(pass.FailedIDs) != 0 {
		t.Fatalf("passing run = %+v, want exit 0 and no failures", pass)
	}
	if pass.FailedIDs == nil {
		t.Fatal("FailedIDs must be an empty slice, not nil, so it serializes as []")
	}

	fail, err := Run(context.Background(), dir, "exit 7", spec.ParserExitCode)
	if err != nil {
		t.Fatal(err)
	}
	if fail.ExitCode != 7 || len(fail.FailedIDs) != 1 || fail.FailedIDs[0] != "exit:7" {
		t.Fatalf("failing run = %+v, want the failure id exit:7", fail)
	}
}

func TestParseJUnit(t *testing.T) {
	tests := []struct {
		name       string
		report     string
		wantTotal  int
		wantFailed []string
	}{
		{
			name: "testsuites root",
			report: `<?xml version="1.0"?>
<testsuites>
  <testsuite name="shop" tests="2">
    <testcase classname="shop" name="TestOK"/>
    <testcase classname="shop" name="TestBroken"><failure message="boom"/></testcase>
  </testsuite>
</testsuites>`,
			wantTotal:  2,
			wantFailed: []string{"shop.TestBroken"},
		},
		{
			name: "single testsuite root and an error",
			report: `<testsuite name="shop">
  <testcase classname="shop" name="TestOK"/>
  <testcase classname="shop" name="TestError"><error message="panic"/></testcase>
</testsuite>`,
			wantTotal:  2,
			wantFailed: []string{"shop.TestError"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total, failed, err := parseJUnit([]byte(tt.report))
			if err != nil {
				t.Fatal(err)
			}
			if total != tt.wantTotal {
				t.Fatalf("total = %d, want %d", total, tt.wantTotal)
			}
			if len(failed) != len(tt.wantFailed) {
				t.Fatalf("failed = %v, want %v", failed, tt.wantFailed)
			}
			for i := range failed {
				if failed[i] != tt.wantFailed[i] {
					t.Fatalf("failed[%d] = %q, want %q", i, failed[i], tt.wantFailed[i])
				}
			}
		})
	}
}

func TestParseJUnitRejectsNonReports(t *testing.T) {
	if _, _, err := parseJUnit([]byte("go test: no report here\n")); err == nil {
		t.Fatal("parseJUnit accepted output that is not XML")
	}
	if _, _, err := parseJUnit([]byte("<testsuites></testsuites>")); err == nil {
		t.Fatal("parseJUnit accepted a report with no testcase")
	}
}
