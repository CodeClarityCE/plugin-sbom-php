package performance

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
)

// PerformanceManager coordinates all performance optimizations
type PerformanceManager struct {
	httpClient       *OptimizedHTTPClient
	jsonParser       *StreamingJSONParser
	objectPool       *ObjectPool
	concurrentEngine *ConcurrentEngine

	// Configuration
	config PerformanceConfig

	// Statistics
	mu           sync.RWMutex
	overallStats OverallStats
}

// PerformanceConfig holds performance optimization settings
type PerformanceConfig struct {
	// HTTP settings
	HTTPTimeout             time.Duration
	MaxConcurrentRequests   int
	EnableConnectionPooling bool

	// JSON parsing settings
	JSONBufferSize     int
	StreamingThreshold int64 // File size threshold for streaming

	// Concurrency settings
	WorkerCount       int
	ProcessingTimeout time.Duration

	// Memory settings
	EnableObjectPooling bool
	MaxPooledObjects    int

	// Caching settings
	EnableFileCache bool
	CacheTTL        time.Duration
}

// OverallStats provides comprehensive performance metrics
type OverallStats struct {
	StartTime           time.Time
	TotalAnalysisTime   time.Duration
	FilesProcessed      int64
	PackagesProcessed   int64
	HTTPRequestsMade    int64
	CacheHitsTotal      int64
	MemoryOptimizations int64
	ConcurrentTasks     int64
}

// DefaultPerformanceConfig returns optimized default configuration
func DefaultPerformanceConfig() PerformanceConfig {
	return PerformanceConfig{
		HTTPTimeout:             30 * time.Second,
		MaxConcurrentRequests:   20,
		EnableConnectionPooling: true,
		JSONBufferSize:          64 * 1024,   // 64KB
		StreamingThreshold:      1024 * 1024, // 1MB
		WorkerCount:             0,           // Auto-detect based on CPU count
		ProcessingTimeout:       5 * time.Minute,
		EnableObjectPooling:     true,
		MaxPooledObjects:        1000,
		EnableFileCache:         true,
		CacheTTL:                1 * time.Hour,
	}
}

// NewPerformanceManager creates a new performance manager with optimizations
func NewPerformanceManager(config PerformanceConfig) *PerformanceManager {
	manager := &PerformanceManager{
		config:       config,
		overallStats: OverallStats{StartTime: time.Now()},
	}

	// Initialize HTTP client with connection pooling
	if config.EnableConnectionPooling {
		manager.httpClient = NewOptimizedHTTPClient(config.HTTPTimeout)
		log.Println("Performance: HTTP connection pooling enabled")
	}

	// Initialize streaming JSON parser
	manager.jsonParser = NewStreamingJSONParser(config.JSONBufferSize)
	log.Printf("Performance: JSON streaming enabled (threshold: %d bytes)", config.StreamingThreshold)

	// Initialize object pool
	if config.EnableObjectPooling {
		manager.objectPool = NewObjectPool()
		log.Println("Performance: Object pooling enabled")
	}

	// Initialize concurrent processing engine
	manager.concurrentEngine = NewConcurrentEngine(config.WorkerCount)
	log.Printf("Performance: Concurrent processing enabled (%d workers)", manager.concurrentEngine.GetWorkerCount())

	return manager
}

// ParseComposerFilesOptimized parses composer files with all optimizations
func (pm *PerformanceManager) ParseComposerFilesOptimized(composerJSONPath, composerLockPath string) (*parser.ComposerJSON, *parser.ComposerLock, error) {
	start := time.Now()
	defer func() {
		pm.updateStats(func(s *OverallStats) {
			s.TotalAnalysisTime += time.Since(start)
			s.FilesProcessed += 2 // composer.json + composer.lock
		})
	}()

	// Parse files concurrently
	type parseResult struct {
		composerJSON *parser.ComposerJSON
		composerLock *parser.ComposerLock
		jsonErr      error
		lockErr      error
	}

	resultChan := make(chan parseResult, 1)

	go func() {
		var result parseResult
		var wg sync.WaitGroup

		// Parse composer.json
		wg.Add(1)
		go func() {
			defer wg.Done()
			result.composerJSON, result.jsonErr = pm.jsonParser.ParseComposerJSONOptimized(composerJSONPath)
		}()

		// Parse composer.lock
		wg.Add(1)
		go func() {
			defer wg.Done()
			if composerLockPath != "" {
				result.composerLock, result.lockErr = pm.jsonParser.ParseComposerLockOptimized(composerLockPath)
			}
		}()

		wg.Wait()
		resultChan <- result
	}()

	result := <-resultChan

	// Handle errors
	if result.jsonErr != nil {
		return nil, nil, fmt.Errorf("failed to parse composer.json: %w", result.jsonErr)
	}

	if result.lockErr != nil && composerLockPath != "" {
		log.Printf("Warning: failed to parse composer.lock: %v", result.lockErr)
		// Continue without composer.lock
	}

	return result.composerJSON, result.composerLock, nil
}

// ProcessPackagesConcurrently processes multiple packages in parallel
func (pm *PerformanceManager) ProcessPackagesConcurrently(packages []parser.PackageInfo, processFunc func(context.Context, parser.PackageInfo) (parser.PackageInfo, error)) ([]parser.PackageInfo, []error) {
	start := time.Now()
	defer func() {
		pm.updateStats(func(s *OverallStats) {
			s.PackagesProcessed += int64(len(packages))
			s.ConcurrentTasks++
		})
	}()

	// Convert to interface{} slice for generic processing
	items := make([]interface{}, len(packages))
	for i, pkg := range packages {
		items[i] = pkg
	}

	// Create wrapper function
	wrapperFunc := func(ctx context.Context, item interface{}) (interface{}, error) {
		pkg, ok := item.(parser.PackageInfo)
		if !ok {
			return nil, fmt.Errorf("invalid type conversion")
		}
		return processFunc(ctx, pkg)
	}

	// Use concurrent engine for processing
	result := pm.concurrentEngine.ProcessBatch(items, wrapperFunc)

	// Convert results back to typed slices
	results := make([]parser.PackageInfo, len(result.Results))
	for i, res := range result.Results {
		if res != nil {
			if pkg, ok := res.(parser.PackageInfo); ok {
				results[i] = pkg
			}
		}
	}

	log.Printf("Performance: Processed %d packages concurrently in %v (%.2f pkg/sec)",
		len(packages), time.Since(start), result.Stats.Throughput)

	return results, result.Errors
}

// OptimizeHTTPRequests performs HTTP requests with connection pooling
func (pm *PerformanceManager) OptimizeHTTPRequests(urls []string, requestFunc func(*OptimizedHTTPClient, string) error) []error {
	if pm.httpClient == nil {
		return []error{fmt.Errorf("HTTP client not initialized")}
	}

	start := time.Now()
	defer func() {
		pm.updateStats(func(s *OverallStats) {
			s.HTTPRequestsMade += int64(len(urls))
		})
	}()

	errors := make([]error, len(urls))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, pm.config.MaxConcurrentRequests)

	for i, url := range urls {
		wg.Add(1)
		go func(index int, u string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			errors[index] = requestFunc(pm.httpClient, u)
		}(i, url)
	}

	wg.Wait()

	stats := pm.httpClient.GetStats()
	log.Printf("Performance: Completed %d HTTP requests in %v (avg: %v, reuse: %d)",
		len(urls), time.Since(start), stats.AverageLatency, stats.ConnectionReuse)

	return errors
}

// GetOptimizedObjectPool returns the object pool for memory optimization
func (pm *PerformanceManager) GetOptimizedObjectPool() *ObjectPool {
	return pm.objectPool
}

// GetStats returns comprehensive performance statistics
func (pm *PerformanceManager) GetStats() PerformanceStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var httpStats HTTPStats
	var jsonStats JSONStats
	var poolStats PoolStats
	var concurrencyStats ConcurrencyStats

	if pm.httpClient != nil {
		httpStats = pm.httpClient.GetStats()
	}

	if pm.jsonParser != nil {
		jsonStats = pm.jsonParser.GetStats()
	}

	if pm.objectPool != nil {
		poolStats = pm.objectPool.GetStats()
	}

	if pm.concurrentEngine != nil {
		concurrencyStats = pm.concurrentEngine.GetStats()
	}

	return PerformanceStats{
		Overall:     pm.overallStats,
		HTTP:        httpStats,
		JSON:        jsonStats,
		ObjectPool:  poolStats,
		Concurrency: concurrencyStats,
		Config:      pm.config,
	}
}

// PerformanceStats aggregates all performance metrics
type PerformanceStats struct {
	Overall     OverallStats
	HTTP        HTTPStats
	JSON        JSONStats
	ObjectPool  PoolStats
	Concurrency ConcurrencyStats
	Config      PerformanceConfig
}

// PrintPerformanceReport prints a detailed performance report
func (pm *PerformanceManager) PrintPerformanceReport() {
	stats := pm.GetStats()

	fmt.Println("=== PHP SBOM Performance Report ===")
	fmt.Printf("Total Analysis Time: %v\n", stats.Overall.TotalAnalysisTime)
	fmt.Printf("Files Processed: %d\n", stats.Overall.FilesProcessed)
	fmt.Printf("Packages Processed: %d\n", stats.Overall.PackagesProcessed)
	fmt.Printf("HTTP Requests Made: %d\n", stats.Overall.HTTPRequestsMade)

	if stats.HTTP.TotalRequests > 0 {
		fmt.Printf("HTTP Success Rate: %.1f%%\n",
			float64(stats.HTTP.SuccessfulReqs)/float64(stats.HTTP.TotalRequests)*100)
		fmt.Printf("HTTP Average Latency: %v\n", stats.HTTP.AverageLatency)
		fmt.Printf("HTTP Connection Reuse: %d\n", stats.HTTP.ConnectionReuse)
	}

	if stats.JSON.FilesProcessed > 0 {
		fmt.Printf("JSON Files Processed: %d\n", stats.JSON.FilesProcessed)
		fmt.Printf("JSON Streaming Used: %d times\n", stats.JSON.StreamingUsed)
		fmt.Printf("JSON Memory Parsing Used: %d times\n", stats.JSON.MemoryParsingUsed)
		fmt.Printf("Largest File Processed: %d bytes\n", stats.JSON.LargestFile)
	}

	if pm.objectPool != nil {
		fmt.Printf("Object Pool Reuse Efficiency: %.1f%%\n",
			pm.objectPool.GetReuseEfficiency())
		fmt.Printf("Objects Reused: %d\n", stats.ObjectPool.TotalReuse)
	}

	if stats.Concurrency.TasksProcessed > 0 {
		fmt.Printf("Concurrent Tasks Processed: %d\n", stats.Concurrency.TasksProcessed)
		fmt.Printf("Peak Concurrency: %d\n", stats.Concurrency.PeakConcurrency)
		fmt.Printf("Average Task Time: %v\n", stats.Concurrency.AverageTaskTime)
	}

	fmt.Println("================================")
}

// Shutdown gracefully shuts down all performance components
func (pm *PerformanceManager) Shutdown(timeout time.Duration) error {
	var errors []error

	// Shutdown concurrent engine
	if pm.concurrentEngine != nil {
		if err := pm.concurrentEngine.Shutdown(timeout); err != nil {
			errors = append(errors, fmt.Errorf("concurrent engine shutdown: %w", err))
		}
	}

	// Close HTTP client
	if pm.httpClient != nil {
		if err := pm.httpClient.Close(); err != nil {
			errors = append(errors, fmt.Errorf("HTTP client close: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	log.Println("Performance manager shutdown completed")
	return nil
}

// updateStats safely updates overall statistics
func (pm *PerformanceManager) updateStats(updateFunc func(*OverallStats)) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	updateFunc(&pm.overallStats)
}

// ResetStats resets all performance statistics
func (pm *PerformanceManager) ResetStats() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.overallStats = OverallStats{StartTime: time.Now()}

	if pm.httpClient != nil {
		pm.httpClient.ResetStats()
	}

	if pm.jsonParser != nil {
		pm.jsonParser.ResetStats()
	}

	if pm.objectPool != nil {
		pm.objectPool.ResetStats()
	}

	if pm.concurrentEngine != nil {
		pm.concurrentEngine.ResetStats()
	}
}
