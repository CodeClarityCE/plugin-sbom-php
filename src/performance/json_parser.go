package performance

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/CodeClarityCE/plugin-php-sbom/src/parser"
)

// StreamingJSONParser provides optimized JSON parsing for large composer.lock files
type StreamingJSONParser struct {
	bufferSize int
	mu         sync.RWMutex
	stats      JSONStats
}

// JSONStats tracks JSON parsing performance
type JSONStats struct {
	FilesProcessed    int64
	TotalBytesRead    int64
	LargestFile       int64
	TotalParseTime    int64 // nanoseconds
	StreamingUsed     int64
	MemoryParsingUsed int64
}

// NewStreamingJSONParser creates a new optimized JSON parser
func NewStreamingJSONParser(bufferSize int) *StreamingJSONParser {
	if bufferSize <= 0 {
		bufferSize = 64 * 1024 // 64KB default buffer
	}

	return &StreamingJSONParser{
		bufferSize: bufferSize,
		stats:      JSONStats{},
	}
}

// ParseComposerLockOptimized parses a composer.lock file with performance optimization
func (p *StreamingJSONParser) ParseComposerLockOptimized(filePath string) (*parser.ComposerLock, error) {
	// Get file size to determine parsing strategy
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat composer.lock: %w", err)
	}

	fileSize := fileInfo.Size()
	p.updateStats(func(s *JSONStats) {
		s.FilesProcessed++
		s.TotalBytesRead += fileSize
		if fileSize > s.LargestFile {
			s.LargestFile = fileSize
		}
	})

	// Use streaming parser for large files (>1MB)
	if fileSize > 1024*1024 {
		return p.parseWithStreaming(filePath)
	}

	// Use memory parser for small files
	return p.parseInMemory(filePath)
}

// parseWithStreaming uses streaming JSON parsing for large files
func (p *StreamingJSONParser) parseWithStreaming(filePath string) (*parser.ComposerLock, error) {
	p.updateStats(func(s *JSONStats) { s.StreamingUsed++ })

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open composer.lock: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, p.bufferSize)
	decoder := json.NewDecoder(reader)

	// Use streaming decoder for memory efficiency
	var composerLock parser.ComposerLock
	if err := decoder.Decode(&composerLock); err != nil {
		return nil, fmt.Errorf("failed to stream parse composer.lock: %w", err)
	}

	return &composerLock, nil
}

// parseInMemory uses traditional in-memory parsing for smaller files
func (p *StreamingJSONParser) parseInMemory(filePath string) (*parser.ComposerLock, error) {
	p.updateStats(func(s *JSONStats) { s.MemoryParsingUsed++ })

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.lock: %w", err)
	}

	var composerLock parser.ComposerLock
	if err := json.Unmarshal(data, &composerLock); err != nil {
		return nil, fmt.Errorf("failed to parse composer.lock: %w", err)
	}

	return &composerLock, nil
}

// ParseComposerJSONOptimized parses composer.json with optimization
func (p *StreamingJSONParser) ParseComposerJSONOptimized(filePath string) (*parser.ComposerJSON, error) {
	// composer.json files are typically small, use memory parsing
	p.updateStats(func(s *JSONStats) {
		s.FilesProcessed++
		s.MemoryParsingUsed++
	})

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read composer.json: %w", err)
	}

	p.updateStats(func(s *JSONStats) { s.TotalBytesRead += int64(len(data)) })

	var composerJSON parser.ComposerJSON
	if err := json.Unmarshal(data, &composerJSON); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	return &composerJSON, nil
}

// ParsePackagesBatch parses multiple packages concurrently
func (p *StreamingJSONParser) ParsePackagesBatch(packages []parser.PackageInfo, batchSize int) ([]parser.PackageInfo, error) {
	if batchSize <= 0 {
		batchSize = 10
	}

	results := make([]parser.PackageInfo, len(packages))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, batchSize)

	for i, pkg := range packages {
		wg.Add(1)
		go func(index int, package_ parser.PackageInfo) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			// Process package (placeholder for actual processing logic)
			results[index] = package_
		}(i, pkg)
	}

	wg.Wait()
	return results, nil
}

// ValidateJSON quickly validates JSON structure without full parsing
func (p *StreamingJSONParser) ValidateJSON(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, p.bufferSize)
	decoder := json.NewDecoder(reader)

	// Validate by attempting to decode to interface{}
	var temp interface{}
	return decoder.Decode(&temp)
}

// OptimizeJSONString removes unnecessary whitespace from JSON strings
func (p *StreamingJSONParser) OptimizeJSONString(jsonStr string) string {
	// Remove extra whitespace while preserving structure
	lines := strings.Split(jsonStr, "\n")
	var optimized strings.Builder
	optimized.Grow(len(jsonStr) * 3 / 4) // Estimate 25% size reduction

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			optimized.WriteString(trimmed)
		}
	}

	return optimized.String()
}

// GetStats returns current JSON parsing statistics
func (p *StreamingJSONParser) GetStats() JSONStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// ResetStats resets parsing statistics
func (p *StreamingJSONParser) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats = JSONStats{}
}

// updateStats safely updates statistics
func (p *StreamingJSONParser) updateStats(updateFunc func(*JSONStats)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	updateFunc(&p.stats)
}

// CheckJSONHealth performs health check on JSON parsing capability
func (p *StreamingJSONParser) CheckJSONHealth() error {
	// Test with a simple JSON structure
	testJSON := `{"test": "value", "number": 123}`
	reader := strings.NewReader(testJSON)
	decoder := json.NewDecoder(reader)

	var temp map[string]interface{}
	return decoder.Decode(&temp)
}

// GetOptimalBufferSize calculates optimal buffer size based on file size
func (p *StreamingJSONParser) GetOptimalBufferSize(fileSize int64) int {
	switch {
	case fileSize < 10*1024: // < 10KB
		return 4 * 1024 // 4KB buffer
	case fileSize < 100*1024: // < 100KB
		return 16 * 1024 // 16KB buffer
	case fileSize < 1024*1024: // < 1MB
		return 64 * 1024 // 64KB buffer
	default: // >= 1MB
		return 256 * 1024 // 256KB buffer
	}
}
