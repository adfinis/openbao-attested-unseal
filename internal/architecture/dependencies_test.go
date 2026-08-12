package architecture_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/adfinis/openbao-attested-unseal"

type importEdge struct {
	from string
	to   string
	file string
}

type dependencyPolicy struct {
	name      string
	fromTrees []string
	denyTrees []string
}

func TestPackageDependencyDirection(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	edges := productionImportEdges(t, root)
	policies := []dependencyPolicy{
		{
			name: "domain packages do not depend on runtime or transport details",
			fromTrees: []string{
				modulePath + "/internal/enrollment",
				modulePath + "/internal/keyring",
				modulePath + "/internal/nodeevidence",
				modulePath + "/internal/recovery",
				modulePath + "/internal/tpm",
			},
			denyTrees: []string{
				modulePath + "/internal/baounsealagent",
				modulePath + "/internal/baounsealctl",
				modulePath + "/internal/baounseald",
				modulePath + "/internal/broker",
				modulePath + "/internal/brokeradmin",
				modulePath + "/internal/kmsplugin",
				modulePath + "/internal/nodeagent",
				modulePath + "/internal/protocol",
				modulePath + "/internal/transport",
			},
		},
		{
			name: "node evidence adapters do not depend on the broker runtime",
			fromTrees: []string{
				modulePath + "/internal/baounsealagent",
				modulePath + "/internal/brokeradmin",
				modulePath + "/internal/nodeagent",
			},
			denyTrees: []string{modulePath + "/internal/broker"},
		},
	}

	for _, policy := range policies {
		t.Run(policy.name, func(t *testing.T) {
			t.Parallel()
			for _, edge := range edges {
				if inAnyPackageTree(edge.from, policy.fromTrees) && inAnyPackageTree(edge.to, policy.denyTrees) {
					t.Errorf("forbidden dependency %s -> %s in %s", edge.from, edge.to, edge.file)
				}
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func productionImportEdges(t *testing.T, root string) []importEdge {
	t.Helper()
	internalRoot := filepath.Join(root, "internal")
	edges := make([]importEdge, 0)
	err := filepath.WalkDir(internalRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		relativeDir, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		importer := modulePath + "/" + filepath.ToSlash(relativeDir)
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			edges = append(edges, importEdge{
				from: importer,
				to:   imported,
				file: filepath.ToSlash(path),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect production imports: %v", err)
	}
	return edges
}

func inAnyPackageTree(pkg string, trees []string) bool {
	for _, tree := range trees {
		if pkg == tree || strings.HasPrefix(pkg, tree+"/") {
			return true
		}
	}
	return false
}
