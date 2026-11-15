package bcr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bazelbuild/bazel-gazelle/rule"
	"github.com/bazelbuild/buildtools/build"
)

const firstMaterializationModuleTemplate = `module(name = "bcr_published_docs_first_materialization")

http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
`

type firstMaterializationReceipt struct {
	AttackModuleSHA256  string            `json:"attack_module_sha256"`
	AttackRuleSHA256    string            `json:"attack_rule_sha256"`
	ControlModuleSHA256 string            `json:"control_module_sha256"`
	ControlRuleSHA256   string            `json:"control_rule_sha256"`
	ExpectedSHA256      string            `json:"expected_sha256"`
	FrontendCommit      string            `json:"frontend_commit"`
	ProductionFunction  string            `json:"production_function"`
	ProductionHasSHA256 bool              `json:"production_has_sha256"`
	RuleDifference      map[string]string `json:"rule_difference"`
	TargetLabel         string            `json:"target_label"`
	TargetRepository    string            `json:"target_repository"`
	TargetURL           string            `json:"target_url"`
	WarmLabel           string            `json:"warm_label"`
	WarmRepository      string            `json:"warm_repository"`
	WarmURL             string            `json:"warm_url"`
}

func firstRequiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func firstRender(t *testing.T, template []byte, rules ...*rule.Rule) []byte {
	t.Helper()
	ast, err := build.ParseModule("MODULE.bazel", template)
	if err != nil {
		t.Fatal(err)
	}
	f := rule.ScanAST("", ast)
	for _, r := range rules {
		r.Insert(f)
	}
	f.Sync()
	return f.Format()
}

func firstDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func TestEmitProductionFirstMaterializationModules(t *testing.T) {
	warmURL := firstRequiredEnv(t, "PROOF_WARM_DOCS_URL")
	targetURL := firstRequiredEnv(t, "PROOF_TARGET_DOCS_URL")
	expectedSHA := firstRequiredEnv(t, "PROOF_REVIEWED_SHA256")
	outputDir := firstRequiredEnv(t, "PROOF_OUTPUT_DIR")
	frontendCommit := firstRequiredEnv(t, "PROOF_FRONTEND_COMMIT")
	for _, url := range []string{warmURL, targetURL} {
		if !strings.HasPrefix(url, "https://") || strings.Contains(strings.TrimPrefix(url, "https://"), ":") {
			t.Fatalf("docs URL must be HTTPS without a port: %s", url)
		}
	}
	if warmURL == targetURL {
		t.Fatal("warm and target URLs must differ")
	}
	if len(expectedSHA) != 64 {
		t.Fatalf("reviewed SHA-256 has invalid length: %s", expectedSHA)
	}

	warmLabel := makeBinaryProtoRepositoryLabel(warmURL)
	targetLabel := makeBinaryProtoRepositoryLabel(targetURL)
	makeWarmRule := func() *rule.Rule { return makeBinaryProtoRepository(warmLabel, warmURL) }
	makeAttackRule := func() *rule.Rule { return makeBinaryProtoRepository(targetLabel, targetURL) }
	makeControlRule := func() *rule.Rule {
		r := makeBinaryProtoRepository(targetLabel, targetURL)
		r.SetAttr("sha256", expectedSHA)
		return r
	}
	attackRule := makeAttackRule()
	controlRule := makeControlRule()
	if attackRule.Kind() != httpArchiveKind || attackRule.AttrString("sha256") != "" || attackRule.AttrString("integrity") != "" {
		t.Fatal("production target rule unexpectedly enforces integrity")
	}
	for _, attr := range []string{"url", "build_file_content"} {
		if !reflect.DeepEqual(attackRule.Attr(attr), controlRule.Attr(attr)) {
			t.Fatalf("attack/control differ at %s", attr)
		}
	}

	warmModule := firstRender(t, []byte(firstMaterializationModuleTemplate), makeWarmRule())
	attackModule := firstRender(t, []byte(firstMaterializationModuleTemplate), makeWarmRule(), makeAttackRule())
	controlModule := firstRender(t, []byte(firstMaterializationModuleTemplate), makeWarmRule(), makeControlRule())
	attackRuleBytes := firstRender(t, nil, makeAttackRule())
	controlRuleBytes := firstRender(t, nil, makeControlRule())
	if strings.Replace(string(controlRuleBytes), fmt.Sprintf("    sha256 = %q,\n", expectedSHA), "", 1) != string(attackRuleBytes) {
		t.Fatal("control target rule differs from production output by more than sha256")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"warm.MODULE.bazel":         warmModule,
		"attack.MODULE.bazel":       attackModule,
		"attack-rule.MODULE.bazel":  attackRuleBytes,
		"control.MODULE.bazel":      controlModule,
		"control-rule.MODULE.bazel": controlRuleBytes,
	} {
		if err := os.WriteFile(filepath.Join(outputDir, name), payload, 0644); err != nil {
			t.Fatal(err)
		}
	}
	receipt := firstMaterializationReceipt{
		AttackModuleSHA256:  firstDigest(attackModule),
		AttackRuleSHA256:    firstDigest(attackRuleBytes),
		ControlModuleSHA256: firstDigest(controlModule),
		ControlRuleSHA256:   firstDigest(controlRuleBytes),
		ExpectedSHA256:      expectedSHA,
		FrontendCommit:      frontendCommit,
		ProductionFunction:  "language/bcr.makeBinaryProtoRepository",
		ProductionHasSHA256: false,
		RuleDifference:      map[string]string{"control_only": "sha256 = " + expectedSHA},
		TargetLabel:         targetLabel.String(),
		TargetRepository:    targetLabel.Repo,
		TargetURL:           targetURL,
		WarmLabel:           warmLabel.String(),
		WarmRepository:      warmLabel.Repo,
		WarmURL:             warmURL,
	}
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, "emitter-receipt.json"), payload, 0644); err != nil {
		t.Fatal(err)
	}
}
