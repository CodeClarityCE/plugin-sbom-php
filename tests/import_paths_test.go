package main

import (
	"encoding/json"
	"testing"

	plugin "github.com/CodeClarityCE/plugin-php-sbom/src"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// importInfo is the import path part of one dependency version, read from the JSON output.
type importInfo struct {
	IsTopLevel     bool       `json:"is_top_level"`
	TopLevel       []string   `json:"importing_top_level_dependencies"`
	ImportPaths    [][]string `json:"import_paths"`
	DevImportPaths [][]string `json:"dev_import_paths"`
}

// importInfoOf runs the plugin on a fixture and returns workspace -> "name@version" -> import info.
func importInfoOf(t *testing.T, fixture string) map[string]map[string]importInfo {
	t.Helper()
	dir, _ := useFixture(t, fixture)
	out := plugin.Start(dir, uuid.UUID{}, nil)
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Workspaces map[string]struct {
			Dependencies map[string]map[string]importInfo `json:"dependencies"`
		} `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	result := map[string]map[string]importInfo{}
	for wsName, ws := range parsed.Workspaces {
		result[wsName] = map[string]importInfo{}
		for name, versions := range ws.Dependencies {
			for version, info := range versions {
				result[wsName][name+"@"+version] = info
			}
		}
	}
	return result
}

func TestImportPathsDirectDependencyIsItsOwnPath(t *testing.T) {
	deps := importInfoOf(t, "test9-import-paths")["."]

	// acme/shared requires acme/app back, so the walk must stop at the cycle.
	assert.Equal(t, importInfo{
		IsTopLevel:     true,
		TopLevel:       []string{"acme/app@1.0.0", "acme/tool@2.0.0"},
		ImportPaths:    [][]string{{"acme/app@1.0.0"}},
		DevImportPaths: [][]string{{"acme/tool@2.0.0", "acme/shared@1.2.0", "acme/app@1.0.0"}},
	}, deps["acme/app@1.0.0"])
	assert.Equal(t, importInfo{
		IsTopLevel:     true,
		TopLevel:       []string{"acme/tool@2.0.0"},
		ImportPaths:    [][]string{},
		DevImportPaths: [][]string{{"acme/tool@2.0.0"}},
	}, deps["acme/tool@2.0.0"])
}

// Composer requires are constraints, so each one resolves to the version the lock installs.
func TestImportPathsTransitiveListsEveryTopLevelSplitByDevAndProd(t *testing.T) {
	deps := importInfoOf(t, "test9-import-paths")["."]

	assert.Equal(t, importInfo{
		IsTopLevel:     false,
		TopLevel:       []string{"acme/app@1.0.0", "acme/tool@2.0.0"},
		ImportPaths:    [][]string{{"acme/app@1.0.0", "acme/shared@1.2.0", "acme/leaf@1.0.3"}},
		DevImportPaths: [][]string{{"acme/tool@2.0.0", "acme/shared@1.2.0", "acme/leaf@1.0.3"}},
	}, deps["acme/leaf@1.0.3"])
	assert.Equal(t, importInfo{
		IsTopLevel:     false,
		TopLevel:       []string{"acme/tool@2.0.0"},
		ImportPaths:    [][]string{},
		DevImportPaths: [][]string{{"acme/tool@2.0.0", "acme/devonly@0.1.0"}},
	}, deps["acme/devonly@0.1.0"])
}

func TestImportPathsStayWithinTheirWorkspace(t *testing.T) {
	workspaces := importInfoOf(t, "test9-import-paths")

	assert.Equal(t, map[string]importInfo{
		"acme/leaf@1.0.3": {
			IsTopLevel:     true,
			TopLevel:       []string{"acme/leaf@1.0.3"},
			ImportPaths:    [][]string{{"acme/leaf@1.0.3"}},
			DevImportPaths: [][]string{},
		},
	}, workspaces["packages/lib/composer.json"])
}
