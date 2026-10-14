// extra_test.go — 对照 selftest_extra_expected.json 跑全量比对
package fingerprint_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danche23/banner-fingerprint/internal/fingerprint"
	"github.com/danche23/banner-fingerprint/internal/model"
)

type extraExpected struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

func projectRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// internal/fingerprint/extra_test.go -> up 3 levels
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func TestExtraDataset(t *testing.T) {
	root := projectRoot()
	eng, err := fingerprint.New(filepath.Join(root, "rules", "fingerprints.json"))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	testdataDir := `D:/personal/Workbuddywork/banner-fingerprint/testdata`

	inputBytes, err := os.ReadFile(filepath.Join(testdataDir, "selftest_extra_input.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}
	expectedBytes, err := os.ReadFile(filepath.Join(testdataDir, "selftest_extra_expected.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var inputs []model.BannerInput
	var expected []extraExpected
	if err := json.Unmarshal(inputBytes, &inputs); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		t.Fatalf("parse expected: %v", err)
	}

	if len(inputs) != len(expected) {
		t.Fatalf("length mismatch: input=%d expected=%d", len(inputs), len(expected))
	}

	fail, pass := 0, 0
	type failure struct {
		idx    int
		banner string
		field  string
		got    string
		want   string
	}
	var failures []failure

	for i, inp := range inputs {
		exp := expected[i]
		got := eng.Identify(inp)

		if !strings.EqualFold(got.Protocol, exp.Protocol) {
			failures = append(failures, failure{i, inp.Banner, "protocol", got.Protocol, exp.Protocol})
			fail++
			continue
		}
		pass++
		// 产品名：期望非空时才比对
		if exp.Product != "" && !strings.EqualFold(got.Product, exp.Product) {
			failures = append(failures, failure{i, inp.Banner, "product", got.Product, exp.Product})
		}
		// 版本：期望非空时才比对
		if exp.Version != "" && got.Version != exp.Version {
			failures = append(failures, failure{i, inp.Banner, "version", got.Version, exp.Version})
		}
	}

	t.Logf("PASS=%d FAIL=%d TOTAL=%d", pass, fail, len(inputs))
	for _, f := range failures {
		t.Errorf("[%d] banner=%q  field=%s  got=%q  want=%q", f.idx, f.banner, f.field, f.got, f.want)
	}
}
