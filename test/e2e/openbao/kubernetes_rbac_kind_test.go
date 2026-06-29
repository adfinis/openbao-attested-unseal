//go:build e2e

package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	podUID := strings.TrimSpace(kubectl(
		false,
		"-n", kindNamespace,
		"get", "pod", kindOpenBaoPod,
		"-o", "jsonpath={.metadata.uid}",
	))
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

func TestKubernetesBrokerManifestPublishesFakeNodeEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("kind-backed E2E is not supported on Windows")
	}
	requireDocker(t)
	requireKind(t)
	requireKubectl(t)

	repoRoot := findRepoRoot(t)
	workDir := newE2EWorkDir(t)
	clusterName := fmt.Sprintf("openbao-au-broker-kind-%d-%d", time.Now().UnixNano(), os.Getpid())
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

	nodeName := strings.TrimSpace(kubectl(false, "get", "nodes", "-o", "jsonpath={.items[0].metadata.name}"))
	if nodeName == "" {
		t.Fatal("kind cluster did not return a node name")
	}
	nodeUID := strings.TrimSpace(kubectl(false, "get", "node", nodeName, "-o", "jsonpath={.metadata.uid}"))
	if nodeUID == "" {
		t.Fatal("kind node did not return a UID")
	}

	dockerArch := dockerServerArch(t)
	goarch := dockerGOARCH(t, dockerArch)
	hostCtl := filepath.Join(workDir, "bao-unsealctl-host")
	linuxBroker := filepath.Join(workDir, "bao-unseald-linux")
	buildBinary(t, repoRoot, hostCtl, "", "", "./cmd/bao-unsealctl")
	buildBinary(t, repoRoot, linuxBroker, "linux", goarch, "./cmd/bao-unseald")
	chmod(t, hostCtl, 0o755)
	chmod(t, linuxBroker, 0o755)

	imageTag := fmt.Sprintf("openbao-attested-unseal/bao-unseald:e2e-%d-%d", time.Now().UnixNano(), os.Getpid())
	buildKindBrokerImage(t, workDir, linuxBroker, imageTag)
	if !keep {
		t.Cleanup(func() { dockerIgnore(t, "image", "rm", "-f", imageTag) })
	}
	run(t, false, "kind", "load", "docker-image", "--name", clusterName, imageTag)

	rbacPath := filepath.Join(repoRoot, "deploy", "kubernetes", "rbac.yaml")
	brokerManifestPath := writeKindBrokerManifest(
		t,
		workDir,
		filepath.Join(repoRoot, "deploy", "kubernetes", "bao-unseald.yaml"),
		imageTag,
	)
	kubectl(false, "apply", "-f", rbacPath)
	kubectl(false, "apply", "-f", brokerManifestPath)
	kubectl(false, "-n", kindNamespace, "rollout", "status", "deployment/bao-unseald", "--timeout=90s")

	localPort := freeTCPPort(t)
	stopForward := startKubectlPortForward(
		t,
		kubectlEnv,
		kindNamespace,
		"svc/bao-unseald",
		fmt.Sprintf("%d:8443", localPort),
	)
	defer stopForward()

	publishJSON := run(
		t,
		false,
		hostCtl,
		"k8s", "publish-node",
		"-addr", fmt.Sprintf("127.0.0.1:%d", localPort),
		"-plaintext",
		"-cluster-id", "prod-eu1",
		"-node-name", nodeName,
		"-node-uid", nodeUID,
		"-format", "json",
	)
	var publish struct {
		Decision string `json:"decision"`
		Status   string `json:"status"`
		NodeName string `json:"node_name"`
		NodeUID  string `json:"node_uid"`
	}
	if err := json.Unmarshal([]byte(publishJSON), &publish); err != nil {
		t.Fatalf("parse publish-node JSON returned error: %v\n%s", err, publishJSON)
	}
	if publish.Decision != "allow" || publish.Status != "fresh" {
		t.Fatalf("publish-node result = %#v, want allow/fresh", publish)
	}
	if publish.NodeName != nodeName || publish.NodeUID != nodeUID {
		t.Fatalf("publish-node node = %#v, want %s/%s", publish, nodeName, nodeUID)
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

func buildKindBrokerImage(t *testing.T, dir string, linuxBroker string, imageTag string) {
	t.Helper()
	imageDir := filepath.Join(dir, "broker-image")
	mkdirAll(t, imageDir, 0o700)
	dockerfile := `FROM alpine:3.20
COPY bao-unseald /usr/local/bin/bao-unseald
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/bao-unseald"]
`
	if err := os.WriteFile(filepath.Join(imageDir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("WriteFile Dockerfile returned error: %v", err)
	}
	copyFile(t, linuxBroker, filepath.Join(imageDir, "bao-unseald"), 0o755)
	docker(t, false, "build", "-t", imageTag, imageDir)
}

func writeKindBrokerManifest(t *testing.T, dir string, sourcePath string, imageTag string) string {
	t.Helper()
	// #nosec G304 -- test reads a repository manifest selected by the harness.
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("ReadFile broker manifest returned error: %v", err)
	}
	manifest := strings.ReplaceAll(
		string(raw),
		"ghcr.io/adfinis/openbao-attested-unseal/bao-unseald:0.0.0-dev",
		imageTag,
	)
	path := filepath.Join(dir, "bao-unseald.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("WriteFile broker manifest returned error: %v", err)
	}
	return path
}

func copyFile(t *testing.T, sourcePath string, targetPath string, mode os.FileMode) {
	t.Helper()
	// #nosec G304 -- test copies a harness-built binary selected by the test.
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("ReadFile %s returned error: %v", sourcePath, err)
	}
	if err := os.WriteFile(targetPath, raw, mode); err != nil {
		t.Fatalf("WriteFile %s returned error: %v", targetPath, err)
	}
	if err := os.Chmod(targetPath, mode); err != nil {
		t.Fatalf("Chmod %s returned error: %v", targetPath, err)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func startKubectlPortForward(
	t *testing.T,
	env []string,
	namespace string,
	resource string,
	portMapping string,
) func() {
	t.Helper()
	localPort := strings.Split(portMapping, ":")[0]
	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	//nolint:gosec // E2E harness intentionally invokes the local kubectl CLI.
	cmd := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward", resource, portMapping)
	cmd.Env = env
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("kubectl port-forward start returned error: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Wait() }()

	address := "127.0.0.1:" + localPort
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			cancel()
			t.Fatalf("kubectl port-forward exited early: %v\n%s", err, output.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return func() {
				cancel()
				select {
				case <-errCh:
				case <-time.After(5 * time.Second):
					_ = cmd.Process.Kill()
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	cancel()
	t.Fatalf("kubectl port-forward did not open %s\n%s", address, output.String())
	return func() {}
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
