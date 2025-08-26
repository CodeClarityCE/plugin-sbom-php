package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// ConcurrentEngine provides parallel processing capabilities for SBOM operations
type ConcurrentEngine struct {
	workerCount int
	semaphore   chan struct{}
	stats       ConcurrencyStats
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// ConcurrencyStats tracks concurrent processing performance
type ConcurrencyStats struct {
	TasksProcessed      int64
	TasksSucceeded      int64
	TasksFailed         int64
	TotalProcessingTime time.Duration
	AverageTaskTime     time.Duration
	PeakConcurrency     int
	CurrentActive       int
}

// TaskFunc represents a function that can be executed concurrently
type TaskFunc func(ctx context.Context, item interface{}) (interface{}, error)

// BatchResult represents the result of batch processing
type BatchResult struct {
	Results []interface{}
	Errors  []error
	Stats   ProcessingStats
}

// ProcessingStats provides detailed processing statistics
type ProcessingStats struct {
	TotalItems      int
	SuccessfulItems int
	FailedItems     int
	Duration        time.Duration
	Throughput      float64 // items per second
}

// NewConcurrentEngine creates a new concurrent processing engine
func NewConcurrentEngine(workerCount int) *ConcurrentEngine {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU() // Default to number of CPUs
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ConcurrentEngine{
		workerCount: workerCount,
		semaphore:   make(chan struct{}, workerCount),
		stats:       ConcurrencyStats{},
		ctx:         ctx,
		cancel:      cancel,
	}
}

// ProcessBatch processes a batch of items concurrently
func (e *ConcurrentEngine) ProcessBatch(items []interface{}, taskFunc TaskFunc) BatchResult {
	start := time.Now()

	results := make([]interface{}, len(items))
	errors := make([]error, len(items))
	var wg sync.WaitGroup

	// Track peak concurrency
	e.updatePeakConcurrency(len(items))

	for i, item := range items {
		wg.Add(1)
		go func(index int, taskItem interface{}) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case e.semaphore <- struct{}{}:
				defer func() { <-e.semaphore }()
			case <-e.ctx.Done():
				errors[index] = fmt.Errorf("processing cancelled")
				return
			}

			// Update active task count
			e.updateStats(func(s *ConcurrencyStats) { s.CurrentActive++ })
			defer e.updateStats(func(s *ConcurrencyStats) { s.CurrentActive-- })

			// Process the item
			taskStart := time.Now()
			result, err := taskFunc(e.ctx, taskItem)
			taskDuration := time.Since(taskStart)

			// Store results
			results[index] = result
			errors[index] = err

			// Update statistics
			e.updateStats(func(s *ConcurrencyStats) {
				s.TasksProcessed++
				s.TotalProcessingTime += taskDuration
				s.AverageTaskTime = time.Duration(int64(s.TotalProcessingTime) / s.TasksProcessed)

				if err == nil {
					s.TasksSucceeded++
				} else {
					s.TasksFailed++
				}
			})
		}(i, item)
	}

	wg.Wait()

	// Calculate processing stats
	duration := time.Since(start)
	successCount := 0
	failCount := 0

	for _, err := range errors {
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	throughput := float64(len(items)) / duration.Seconds()

	return BatchResult{
		Results: results,
		Errors:  errors,
		Stats: ProcessingStats{
			TotalItems:      len(items),
			SuccessfulItems: successCount,
			FailedItems:     failCount,
			Duration:        duration,
			Throughput:      throughput,
		},
	}
}

// ProcessPipeline processes items through a pipeline of functions
func (e *ConcurrentEngine) ProcessPipeline(
	items []interface{},
	stages ...TaskFunc,
) BatchResult {
	currentItems := items
	var allErrors []error
	start := time.Now()

	// Process each stage
	for stageIndex, stage := range stages {
		stageStart := time.Now()

		result := e.ProcessBatch(currentItems, stage)

		// Collect non-nil results for next stage
		nextItems := make([]interface{}, 0, len(result.Results))
		for i, item := range result.Results {
			if result.Errors[i] == nil {
				nextItems = append(nextItems, item)
			} else {
				allErrors = append(allErrors,
					fmt.Errorf("stage %d error: %w", stageIndex, result.Errors[i]))
			}
		}

		currentItems = nextItems

		stageDuration := time.Since(stageStart)
		fmt.Printf("Pipeline stage %d completed in %v, %d items remaining\n",
			stageIndex, stageDuration, len(currentItems))

		// Early termination if no items left
		if len(currentItems) == 0 {
			break
		}
	}

	// Prepare final results
	finalResults := make([]interface{}, len(items))
	finalErrors := make([]error, len(items))

	// Fill successful results
	successIndex := 0
	errorIndex := 0

	for i := 0; i < len(items); i++ {
		if errorIndex < len(allErrors) {
			finalErrors[i] = allErrors[errorIndex]
			errorIndex++
		} else if successIndex < len(currentItems) {
			finalResults[i] = currentItems[successIndex]
			successIndex++
		}
	}

	duration := time.Since(start)
	throughput := float64(len(currentItems)) / duration.Seconds()

	return BatchResult{
		Results: finalResults,
		Errors:  finalErrors,
		Stats: ProcessingStats{
			TotalItems:      len(items),
			SuccessfulItems: len(currentItems),
			FailedItems:     len(allErrors),
			Duration:        duration,
			Throughput:      throughput,
		},
	}
}

// ProcessWithTimeout processes items with a timeout
func (e *ConcurrentEngine) ProcessWithTimeout(
	items []interface{},
	taskFunc TaskFunc,
	timeout time.Duration,
) BatchResult {
	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()

	// Create a temporary engine with the timeout context
	tempEngine := &ConcurrentEngine{
		workerCount: e.workerCount,
		semaphore:   make(chan struct{}, e.workerCount),
		stats:       ConcurrencyStats{},
		ctx:         ctx,
		cancel:      cancel,
	}

	return tempEngine.ProcessBatch(items, taskFunc)
}

// ProcessStream processes items from a channel as they arrive
func (e *ConcurrentEngine) ProcessStream(
	input <-chan interface{},
	output chan<- interface{},
	taskFunc TaskFunc,
) {
	var wg sync.WaitGroup

	go func() {
		defer close(output)

		for item := range input {
			wg.Add(1)

			go func(taskItem interface{}) {
				defer wg.Done()

				// Acquire semaphore
				select {
				case e.semaphore <- struct{}{}:
					defer func() { <-e.semaphore }()
				case <-e.ctx.Done():
					return
				}

				// Process item
				result, err := taskFunc(e.ctx, taskItem)
				if err == nil {
					select {
					case output <- result:
					case <-e.ctx.Done():
						return
					}
				}

				// Update stats
				e.updateStats(func(s *ConcurrencyStats) {
					s.TasksProcessed++
					if err == nil {
						s.TasksSucceeded++
					} else {
						s.TasksFailed++
					}
				})
			}(item)
		}

		wg.Wait()
	}()
}

// GetStats returns current concurrency statistics
func (e *ConcurrentEngine) GetStats() ConcurrencyStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// ResetStats resets concurrency statistics
func (e *ConcurrentEngine) ResetStats() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats = ConcurrencyStats{}
}

// SetWorkerCount updates the number of concurrent workers
func (e *ConcurrentEngine) SetWorkerCount(count int) {
	if count <= 0 {
		count = runtime.NumCPU()
	}

	e.workerCount = count
	e.semaphore = make(chan struct{}, count)
}

// GetWorkerCount returns the current worker count
func (e *ConcurrentEngine) GetWorkerCount() int {
	return e.workerCount
}

// Shutdown gracefully shuts down the concurrent engine
func (e *ConcurrentEngine) Shutdown(timeout time.Duration) error {
	done := make(chan struct{})

	go func() {
		// Wait for all active tasks to complete
		for e.stats.CurrentActive > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		close(done)
	}()

	select {
	case <-done:
		e.cancel()
		return nil
	case <-time.After(timeout):
		e.cancel()
		return fmt.Errorf("shutdown timeout after %v", timeout)
	}
}

// GetOptimalWorkerCount calculates optimal worker count based on system resources
func (e *ConcurrentEngine) GetOptimalWorkerCount() int {
	cpuCount := runtime.NumCPU()

	// For I/O bound tasks (like HTTP requests), use more workers than CPUs
	// For CPU bound tasks, use CPU count
	// This is a heuristic that can be tuned based on workload characteristics
	return cpuCount * 2
}

// Helper methods

func (e *ConcurrentEngine) updateStats(updateFunc func(*ConcurrencyStats)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	updateFunc(&e.stats)
}

func (e *ConcurrentEngine) updatePeakConcurrency(potential int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	actual := min(potential, e.workerCount)
	if actual > e.stats.PeakConcurrency {
		e.stats.PeakConcurrency = actual
	}
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
