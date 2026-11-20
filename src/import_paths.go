package src

import (
	"sort"

	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
)

type node struct{ name, version string }

func (n node) key() string { return n.name + VERSION_SEPARATOR + n.version }

// fillImportPaths records, on every version, the top-level dependencies that install it
// and the shortest path from each, split into prod and dev paths.
func fillImportPaths(workspace types.WorkSpace) types.WorkSpace {
	for name, versions := range workspace.Dependencies {
		for version, info := range versions {
			info.IsTopLevel = false
			info.ImportingTopLevelDependencies = []string{}
			info.ImportPaths = [][]string{}
			info.DevImportPaths = [][]string{}
			workspace.Dependencies[name][version] = info
		}
	}

	type start struct {
		root node
		dev  bool
	}
	var starts []start
	for _, dep := range workspace.Start.Dependencies {
		starts = append(starts, start{node{dep.Name, dep.Version}, false})
	}
	for _, dep := range workspace.Start.DevDependencies {
		starts = append(starts, start{node{dep.Name, dep.Version}, true})
	}
	sort.SliceStable(starts, func(i, j int) bool { return starts[i].root.key() < starts[j].root.key() })

	for _, s := range starts {
		if _, ok := workspace.Dependencies[s.root.name][s.root.version]; !ok {
			continue
		}
		for target, path := range shortestPaths(workspace, s.root) {
			info := workspace.Dependencies[target.name][target.version]
			if target == s.root {
				info.IsTopLevel = true
			}
			tops := info.ImportingTopLevelDependencies
			if len(tops) == 0 || tops[len(tops)-1] != s.root.key() {
				info.ImportingTopLevelDependencies = append(tops, s.root.key())
			}
			if s.dev {
				info.DevImportPaths = append(info.DevImportPaths, path)
			} else {
				info.ImportPaths = append(info.ImportPaths, path)
			}
			workspace.Dependencies[target.name][target.version] = info
		}
	}
	return workspace
}

// shortestPaths walks breadth first from root and returns one shortest path to every reachable version.
// Composer requires hold constraints, so each required name resolves to the version the lock installs.
func shortestPaths(workspace types.WorkSpace, root node) map[node][]string {
	paths := map[node][]string{root: {root.key()}}
	queue := []node{root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		requires := workspace.Dependencies[current.name][current.version].Requires
		names := make([]string, 0, len(requires))
		for name := range requires {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			version := getResolvedVersion(name, workspace.Dependencies)
			if version == "" {
				continue // php, extensions and packages missing from the lock
			}
			child := node{name, version}
			if _, seen := paths[child]; seen {
				continue
			}
			paths[child] = append(append([]string{}, paths[current]...), child.key())
			queue = append(queue, child)
		}
	}
	return paths
}
