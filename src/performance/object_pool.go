package performance

import (
	"sync"

	"github.com/CodeClarityCE/plugin-php-sbom/src/types"
)

// ObjectPool provides memory-efficient object reuse for frequently allocated structs
type ObjectPool struct {
	versionPool     sync.Pool
	dependencyPool  sync.Pool
	authorPool      sync.Pool
	workspacePool   sync.Pool
	stringSlicePool sync.Pool
	mapPool         sync.Pool
	stats           PoolStats
	mu              sync.RWMutex
}

// PoolStats tracks object pool performance
type PoolStats struct {
	VersionsCreated     int64
	VersionsReused      int64
	DependenciesCreated int64
	DependenciesReused  int64
	AuthorsCreated      int64
	AuthorsReused       int64
	WorkspacesCreated   int64
	WorkspacesReused    int64
	MapsCreated         int64
	MapsReused          int64
	TotalAllocations    int64
	TotalReuse          int64
}

// NewObjectPool creates a new object pool for SBOM structures
func NewObjectPool() *ObjectPool {
	pool := &ObjectPool{
		stats: PoolStats{},
	}

	// Initialize version pool
	pool.versionPool.New = func() interface{} {
		pool.updateStats(func(s *PoolStats) { s.VersionsCreated++ })
		return &types.Versions{}
	}

	// Initialize workspace dependency pool
	pool.dependencyPool.New = func() interface{} {
		pool.updateStats(func(s *PoolStats) { s.DependenciesCreated++ })
		return &types.WorkSpaceDependency{}
	}

	// Initialize author pool
	pool.authorPool.New = func() interface{} {
		pool.updateStats(func(s *PoolStats) { s.AuthorsCreated++ })
		return &types.Author{}
	}

	// Initialize workspace pool
	pool.workspacePool.New = func() interface{} {
		pool.updateStats(func(s *PoolStats) { s.WorkspacesCreated++ })
		return &types.WorkSpace{
			Dependencies: make(map[string]map[string]types.Versions),
			Start: types.Start{
				Dependencies:    make([]types.WorkSpaceDependency, 0, 10),
				DevDependencies: make([]types.WorkSpaceDependency, 0, 10),
			},
		}
	}

	// Initialize string slice pool for licenses, keywords, etc.
	pool.stringSlicePool.New = func() interface{} {
		slice := make([]string, 0, 5) // Pre-allocate capacity of 5
		return &slice
	}

	// Initialize map pool for requires, dependencies
	pool.mapPool.New = func() interface{} {
		pool.updateStats(func(s *PoolStats) { s.MapsCreated++ })
		m := make(map[string]string, 10) // Pre-allocate capacity of 10
		return &m
	}

	return pool
}

// GetVersions gets a Versions struct from the pool
func (p *ObjectPool) GetVersions() *types.Versions {
	p.updateStats(func(s *PoolStats) {
		s.VersionsReused++
		s.TotalReuse++
	})

	v := p.versionPool.Get().(*types.Versions)
	p.resetVersions(v)
	return v
}

// PutVersions returns a Versions struct to the pool
func (p *ObjectPool) PutVersions(v *types.Versions) {
	if v != nil {
		p.versionPool.Put(v)
	}
}

// GetDependency gets a WorkSpaceDependency from the pool
func (p *ObjectPool) GetDependency() *types.WorkSpaceDependency {
	p.updateStats(func(s *PoolStats) {
		s.DependenciesReused++
		s.TotalReuse++
	})

	dep := p.dependencyPool.Get().(*types.WorkSpaceDependency)
	p.resetDependency(dep)
	return dep
}

// PutDependency returns a WorkSpaceDependency to the pool
func (p *ObjectPool) PutDependency(dep *types.WorkSpaceDependency) {
	if dep != nil {
		p.dependencyPool.Put(dep)
	}
}

// GetAuthor gets an Author from the pool
func (p *ObjectPool) GetAuthor() *types.Author {
	p.updateStats(func(s *PoolStats) {
		s.AuthorsReused++
		s.TotalReuse++
	})

	author := p.authorPool.Get().(*types.Author)
	p.resetAuthor(author)
	return author
}

// PutAuthor returns an Author to the pool
func (p *ObjectPool) PutAuthor(author *types.Author) {
	if author != nil {
		p.authorPool.Put(author)
	}
}

// GetWorkspace gets a WorkSpace from the pool
func (p *ObjectPool) GetWorkspace() *types.WorkSpace {
	p.updateStats(func(s *PoolStats) {
		s.WorkspacesReused++
		s.TotalReuse++
	})

	ws := p.workspacePool.Get().(*types.WorkSpace)
	p.resetWorkspace(ws)
	return ws
}

// PutWorkspace returns a WorkSpace to the pool
func (p *ObjectPool) PutWorkspace(ws *types.WorkSpace) {
	if ws != nil {
		p.workspacePool.Put(ws)
	}
}

// GetStringSlice gets a string slice from the pool
func (p *ObjectPool) GetStringSlice() *[]string {
	slice := p.stringSlicePool.Get().(*[]string)
	*slice = (*slice)[:0] // Reset length but keep capacity
	return slice
}

// PutStringSlice returns a string slice to the pool
func (p *ObjectPool) PutStringSlice(slice *[]string) {
	if slice != nil && cap(*slice) <= 50 { // Don't pool very large slices
		p.stringSlicePool.Put(slice)
	}
}

// GetStringMap gets a string map from the pool
func (p *ObjectPool) GetStringMap() *map[string]string {
	p.updateStats(func(s *PoolStats) {
		s.MapsReused++
		s.TotalReuse++
	})

	m := p.mapPool.Get().(*map[string]string)
	p.resetStringMap(m)
	return m
}

// PutStringMap returns a string map to the pool
func (p *ObjectPool) PutStringMap(m *map[string]string) {
	if m != nil && len(*m) <= 50 { // Don't pool very large maps
		p.mapPool.Put(m)
	}
}

// CreateVersionsBatch creates multiple Versions structs efficiently
func (p *ObjectPool) CreateVersionsBatch(count int) []*types.Versions {
	versions := make([]*types.Versions, count)
	for i := 0; i < count; i++ {
		versions[i] = p.GetVersions()
	}
	return versions
}

// CreateDependenciesBatch creates multiple dependencies efficiently
func (p *ObjectPool) CreateDependenciesBatch(count int) []*types.WorkSpaceDependency {
	deps := make([]*types.WorkSpaceDependency, count)
	for i := 0; i < count; i++ {
		deps[i] = p.GetDependency()
	}
	return deps
}

// ReturnVersionsBatch returns multiple Versions structs to the pool
func (p *ObjectPool) ReturnVersionsBatch(versions []*types.Versions) {
	for _, v := range versions {
		p.PutVersions(v)
	}
}

// ReturnDependenciesBatch returns multiple dependencies to the pool
func (p *ObjectPool) ReturnDependenciesBatch(deps []*types.WorkSpaceDependency) {
	for _, dep := range deps {
		p.PutDependency(dep)
	}
}

// GetStats returns current pool statistics
func (p *ObjectPool) GetStats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := p.stats
	if stats.TotalAllocations > 0 {
		// Calculate reuse percentage
		stats.TotalAllocations = stats.VersionsCreated + stats.DependenciesCreated +
			stats.AuthorsCreated + stats.WorkspacesCreated + stats.MapsCreated
	}

	return stats
}

// ResetStats resets pool statistics
func (p *ObjectPool) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats = PoolStats{}
}

// Helper methods to reset objects before reuse

func (p *ObjectPool) resetVersions(v *types.Versions) {
	v.Key = ""
	v.Requires = nil
	v.Dependencies = nil
	v.Optional = false
	v.Bundled = false
	v.Dev = false
	v.Prod = false
	v.Direct = false
	v.Transitive = false
	v.Licenses = v.Licenses[:0] // Keep slice capacity
	v.PHPVersion = ""
	v.Type = ""
	v.Authors = v.Authors[:0] // Keep slice capacity
	v.Description = ""
}

func (p *ObjectPool) resetDependency(dep *types.WorkSpaceDependency) {
	dep.Name = ""
	dep.Version = ""
	dep.Constraint = ""
}

func (p *ObjectPool) resetAuthor(author *types.Author) {
	author.Name = ""
	author.Email = ""
	author.Role = ""
}

func (p *ObjectPool) resetWorkspace(ws *types.WorkSpace) {
	// Clear the dependencies map but keep the underlying map
	for k := range ws.Dependencies {
		delete(ws.Dependencies, k)
	}

	// Reset slices but keep capacity
	ws.Start.Dependencies = ws.Start.Dependencies[:0]
	ws.Start.DevDependencies = ws.Start.DevDependencies[:0]
}

func (p *ObjectPool) resetStringMap(m *map[string]string) {
	// Clear all entries but keep the map
	for k := range *m {
		delete(*m, k)
	}
}

// updateStats safely updates pool statistics
func (p *ObjectPool) updateStats(updateFunc func(*PoolStats)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	updateFunc(&p.stats)
}

// GetReuseEfficiency calculates the reuse efficiency percentage
func (p *ObjectPool) GetReuseEfficiency() float64 {
	stats := p.GetStats()
	total := stats.TotalAllocations
	if total == 0 {
		return 0.0
	}
	return float64(stats.TotalReuse) / float64(total) * 100.0
}
