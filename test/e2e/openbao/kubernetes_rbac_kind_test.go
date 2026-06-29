//go:build e2e

package openbao

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	kindBrokerSubject = "system:serviceaccount:openbao:bao-unseald"
	kindNamespace     = "openbao"
	kindOpenBaoPod    = "openbao-0"
	kindOpenBaoSA     = "openbao"
)

func TestKubernetesRBACManifestSupportsTokenReviewAndPodLookup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("kind-backed E2E is not supported on Windows")
	}
	requireDocker(t)
	requireKind(t)
	requireKubectl(t)

	repoRoot := findRepoRoot(t)
	workDir := newE2EWorkDir(t)
	clusterName := fmt.Sprintf("openbao-au-rbac-%d-%d", time.Now().UnixNano(), os.Getpid())
	kubeconfig := filepath.Join(workDir, "kind.kubeconfig")
	keep := os.Getenv("OPENBAO_E2E_KEEP") == "1"
	if !keep {
		t.Cleanup(func() { _ = os.RemoveAll(workDir) })
		t.Cleanup(func() {
			output, err := kindOutput("delete", "cluster", "--name", clusterName)
			if err != nil {
				t.Logf("kind delete cluster returned error: %v: %s", err, strings.TrimSpace(output))
			}
		})
	} else {
		t.Logf("OPENBAO_E2E_KEEP=1; keeping kind cluster %s and work dir %s", clusterName, workDir)
	}

	createArgs := []string{"create", "cluster", "--name", clusterName, "--kubeconfig", kubeconfig, "--wait", "90s"}
	if image := strings.TrimSpace(os.Getenv("OPENBAO_E2E_KIND_IMAGE")); image != "" {
		createArgs = append(createArgs, "--image", image)
	}
	run(t, false, "kind", createArgs...)
	kubectlEnv := append(os.Environ(), "KUBECONFIG="+kubeconfig)
	kubectl := func(sensitive bool, args ...string) string {
		t.Helper()
		return runWithEnv(t, sensitive, "", kubectlEnv, "kubectl", args...)
	}

	rbacPath := filepath.Join(repoRoot, "deploy", "kubernetes", "rbac.yaml")
	kubectl(false, "apply", "-f", rbacPath)
	nodeName := strings.TrimSpace(kubectl(false, "get", "nodes", "-o", "jsonpath={.items[0].metadata.name}"))
	if nodeName == "" {
		t.Fatal("kind cluster did not return a node name")
	}
	nodeUID := strings.TrimSpace(kubectl(false, "get", "node", nodeName, "-o", "jsonpath={.metadata.uid}"))
	if nodeUID == "" {
		t.Fatal("kind node did not return a UID")
	}

	podPath := writeKindOpenBaoPod(t, workDir, nodeName)
	kubectl(false, "apply", "-f", podPath)
	podUID := strings.TrimSpace(kubectl(false, "-n", kindNamespace, "get", "pod", kindOpenBaoPod, "-o", "jsonpath={.metadata.uid}"))
	if podUID == "" {
		t.Fatal("OpenBao test Pod did not return a UID")
	}

	assertKubectlYes(
		t,
		kubectl(false, "auth", "can-i", "create", "tokenreviews.authentication.k8s.io", "--as", kindBrokerSubject),
		"TokenReview create permission",
	)
	assertKubectlYes(
		t,
		kubectl(false, "auth", "can-i", "get", "pod/"+kindOpenBaoPod, "-n", kindNamespace, "--as", kindBrokerSubject),
		"OpenBao Pod get permission",
	)

	token := strings.TrimSpace(kubectl(
		true,
		"-n", kindNamespace,
		"create", "token", kindOpenBaoSA,
		"--audience", "bao-unseald",
		"--duration", "10m",
		"--bound-object-kind", "Pod",
		"--bound-object-name", kindOpenBaoPod,
		"--bound-object-uid", podUID,
	))
	if token == "" {
		t.Fatal("kubectl create token returned an empty token")
	}

	reviewPath := writeKindTokenReview(t, workDir, token)
	reviewJSON := kubectlTokenReview(t, kubectlEnv, reviewPath, token)
	review := parseKindTokenReview(t, reviewJSON)
	if !review.Status.Authenticated {
		t.Fatalf("TokenReview authenticated = false: %s", reviewJSON)
	}
	if review.Status.User.Username != "system:serviceaccount:openbao:openbao" {
		t.Fatalf("TokenReview username = %q, want OpenBao service account", review.Status.User.Username)
	}
	assertExtraValue(t, review.Status.User.Extra, "authentication.kubernetes.io/pod-name", kindOpenBaoPod)
	assertExtraValue(t, review.Status.User.Extra, "authentication.kubernetes.io/pod-uid", podUID)
	assertExtraValue(t, review.Status.User.Extra, "authentication.kubernetes.io/node-name", nodeName)
	assertExtraValue(t, review.Status.User.Extra, "authentication.kubernetes.io/node-uid", nodeUID)

	podJSON := kubectl(
		false,
		"--as", kindBrokerSubject,
		"-n", kindNamespace,
		"get", "pod", kindOpenBaoPod,
		"-o", "json",
	)
	pod := parseKindPod(t, podJSON)
	if pod.Metadata.UID != podUID {
		t.Fatalf("Pod lookup UID = %q, want %s", pod.Metadata.UID, podUID)
	}
	if pod.Spec.NodeName != nodeName {
		t.Fatalf("Pod lookup nodeName = %q, want %s", pod.Spec.NodeName, nodeName)
	}
}

func requireKind(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("kind"); err != nil {
		t.Skip("kind is not installed")
	}
	if output, err := kindOutput("version"); err != nil {
		t.Skipf("kind is not available: %v: %s", err, strings.TrimSpace(output))
	}
}

func requireKubectl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl is not installed")
	}
	if output, err := kubectlOutput("version", "--client=true"); err != nil {
		t.Skipf("kubectl is not available: %v: %s", err, strings.TrimSpace(output))
	}
}

func kindOutput(args ...string) (string, error) {
	return commandOutput("kind", args...)
}

func kubectlOutput(args ...string) (string, error) {
	return commandOutput("kubectl", args...)
}

func kubectlTokenReview(t *testing.T, env []string, reviewPath string, token string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	//nolint:gosec // E2E harness intentionally invokes the local kubectl CLI.
	cmd := exec.CommandContext(
		ctx,
		"kubectl",
		"--as", kindBrokerSubject,
		"create", "--validate=false", "-f", reviewPath,
		"-o", "json",
	)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output)
	}
	redacted := strings.ReplaceAll(string(output), token, "[redacted-token]")
	t.Fatalf("kubectl TokenReview failed: %v\n%s", err, redacted)
	return ""
}

func commandOutput(name string, args ...string) (string, error) {
	//nolint:gosec // E2E harness intentionally invokes local CLI tools.
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func writeKindOpenBaoPod(t *testing.T, dir string, nodeName string) string {
	t.Helper()
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: openbao
    app.kubernetes.io/part-of: openbao-attested-unseal
spec:
  serviceAccountName: %s
  nodeName: %s
  containers:
    - name: pause
      image: registry.k8s.io/pause:3.10
`, kindOpenBaoPod, kindNamespace, kindOpenBaoSA, nodeName)
	path := filepath.Join(dir, "openbao-pod.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile Pod manifest returned error: %v", err)
	}
	return path
}

func writeKindTokenReview(t *testing.T, dir string, token string) string {
	t.Helper()
	review := kindTokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: kindTokenReviewSpec{
			Token:     token,
			Audiences: []string{"bao-unseald"},
		},
	}
	encoded, err := json.MarshalIndent(review, "", "  ")
	if err != nil {
		t.Fatalf("Marshal TokenReview returned error: %v", err)
	}
	path := filepath.Join(dir, "tokenreview.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile TokenReview returned error: %v", err)
	}
	return path
}

type kindTokenReviewRequest struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Spec       kindTokenReviewSpec `json:"spec"`
}

type kindTokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type kindTokenReview struct {
	Status struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Username string              `json:"username"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

func parseKindTokenReview(t *testing.T, raw string) kindTokenReview {
	t.Helper()
	var review kindTokenReview
	if err := json.Unmarshal([]byte(raw), &review); err != nil {
		t.Fatalf("parse TokenReview returned error: %v\n%s", err, raw)
	}
	return review
}

type kindPod struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
}

func parseKindPod(t *testing.T, raw string) kindPod {
	t.Helper()
	var pod kindPod
	if err := json.Unmarshal([]byte(raw), &pod); err != nil {
		t.Fatalf("parse Pod returned error: %v\n%s", err, raw)
	}
	return pod
}

func assertKubectlYes(t *testing.T, raw string, label string) {
	t.Helper()
	lines := strings.Split(raw, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if line == "yes" {
			return
		}
		t.Fatalf("%s = %q, want yes", label, line)
	}
	t.Fatalf("%s returned no decision, want yes", label)
}

func assertExtraValue(t *testing.T, extra map[string][]string, key string, want string) {
	t.Helper()
	values := extra[key]
	if len(values) == 0 {
		t.Fatalf("TokenReview extra %q missing", key)
	}
	if values[0] != want {
		t.Fatalf("TokenReview extra %q = %q, want %q", key, values[0], want)
	}
}
