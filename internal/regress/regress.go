// Package regress runs the target's regression command and extracts the set of
// failing tests from it. The pre- and post-patch sets are compared by the
// verdict package: an id that appears only after the patch is a new failure,
// and a new failure breaks the closure conjunction.
package regress

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/SuperMarioYL/pocgate/internal/exec"
	"github.com/SuperMarioYL/pocgate/internal/spec"
)

// Result is one regression run. A non-zero ExitCode is an observation, not an
// error: the failing set is what the gate compares.
type Result struct {
	ExitCode  int
	Total     int
	FailedIDs []string
}

// Run executes the regression command in dir and reads its failure set with the
// declared parser.
//
// The exit_code parser treats the command as a single check: Total is 1 and a
// non-zero exit yields the failure id "exit:<code>". The junit_xml parser reads
// the report from the command's stdout, because the spec carries no report path
// yet.
func Run(ctx context.Context, dir, cmd, parser string) (Result, error) {
	if cmd == "" {
		return Result{}, errors.New("regress: no command")
	}
	run, err := exec.RunShell(ctx, dir, cmd, nil)
	if err != nil {
		return Result{}, err
	}
	result := Result{ExitCode: run.ExitCode, FailedIDs: []string{}}

	switch parser {
	case "", spec.ParserExitCode:
		result.Total = 1
		if run.ExitCode != 0 {
			result.FailedIDs = append(result.FailedIDs, fmt.Sprintf("exit:%d", run.ExitCode))
		}
		return result, nil
	case spec.ParserJUnitXML:
		total, failed, err := parseJUnit(run.Stdout)
		if err != nil {
			return Result{}, err
		}
		result.Total, result.FailedIDs = total, failed
		return result, nil
	default:
		return Result{}, fmt.Errorf("regress: unknown parser %q", parser)
	}
}

// junitNode is a shape-agnostic testsuite element: every child is kept so the
// walk works whether the document root is <testsuites> or <testsuite>.
type junitNode struct {
	XMLName   xml.Name
	Classname string      `xml:"classname,attr"`
	Name      string      `xml:"name,attr"`
	Children  []junitNode `xml:",any"`
}

// parseJUnit counts testcases and collects the ids of the failed ones.
func parseJUnit(data []byte) (int, []string, error) {
	var root junitNode
	if err := xml.Unmarshal(data, &root); err != nil {
		return 0, nil, fmt.Errorf("regress: the command printed no JUnit XML: %w", err)
	}

	total := 0
	failed := []string{}
	var walk func(n junitNode)
	walk = func(n junitNode) {
		if n.XMLName.Local == "testcase" {
			total++
			for _, child := range n.Children {
				if child.XMLName.Local == "failure" || child.XMLName.Local == "error" {
					failed = append(failed, testID(n))
					return
				}
			}
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	walk(root)

	if total == 0 {
		return 0, nil, errors.New("regress: the JUnit XML on stdout contains no testcase")
	}
	return total, failed, nil
}

func testID(n junitNode) string {
	if n.Classname == "" {
		return n.Name
	}
	return n.Classname + "." + n.Name
}
