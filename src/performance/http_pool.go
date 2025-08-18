package performance

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// OptimizedHTTPClient provides an optimized HTTP client with connection pooling
// and performance tuning for SBOM generation workloads
type OptimizedHTTPClient struct {
	client *http.Client
	mu     sync.RWMutex
	stats  HTTPStats
}

// HTTPStats tracks HTTP client performance metrics
type HTTPStats struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedReqs      int64
	TotalTime       time.Duration
	AverageLatency  time.Duration
	CacheHits       int64
	ConnectionReuse int64
}

// NewOptimizedHTTPClient creates a new optimized HTTP client
func NewOptimizedHTTPClient(timeout time.Duration) *OptimizedHTTPClient {
	// Create optimized transport for high-throughput operations
	transport := &http.Transport{
		// Connection pooling settings
		MaxIdleConns:        100,              // Total idle connections across all hosts
		MaxIdleConnsPerHost: 30,               // Idle connections per host
		MaxConnsPerHost:     50,               // Maximum connections per host
		
		// Timeouts
		IdleConnTimeout:       90 * time.Second,  // Keep connections alive longer
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		
		// Dial settings for faster connection establishment
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second, // Connection timeout
			KeepAlive: 30 * time.Second, // TCP keep-alive
			DualStack: true,             // Enable IPv4/IPv6 dual stack
		}).DialContext,
		
		// Performance optimizations
		DisableKeepAlives:     false, // Enable keep-alive for connection reuse
		DisableCompression:    false, // Enable gzip compression for bandwidth
		ForceAttemptHTTP2:     true,  // Use HTTP/2 when available
		WriteBufferSize:       32 * 1024, // 32KB write buffer
		ReadBufferSize:        32 * 1024, // 32KB read buffer
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit redirects to prevent infinite loops
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &OptimizedHTTPClient{
		client: client,
		stats:  HTTPStats{},
	}
}

// Do executes an HTTP request with performance tracking
func (c *OptimizedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	start := time.Now()
	
	c.mu.Lock()
	c.stats.TotalRequests++
	c.mu.Unlock()
	
	resp, err := c.client.Do(req)
	elapsed := time.Since(start)
	
	c.mu.Lock()
	c.stats.TotalTime += elapsed
	c.stats.AverageLatency = time.Duration(int64(c.stats.TotalTime) / c.stats.TotalRequests)
	
	if err != nil {
		c.stats.FailedReqs++
	} else {
		c.stats.SuccessfulReqs++
		
		// Track connection reuse
		if resp.Header.Get("Connection") == "keep-alive" || 
		   resp.ProtoMajor == 2 { // HTTP/2 always reuses connections
			c.stats.ConnectionReuse++
		}
	}
	c.mu.Unlock()
	
	return resp, err
}

// Get performs an optimized GET request
func (c *OptimizedHTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	// Add performance headers
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "php-sbom-plugin/1.0 (optimized)")
	
	return c.Do(req)
}

// Head performs an optimized HEAD request
func (c *OptimizedHTTPClient) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	
	// Add performance headers
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "php-sbom-plugin/1.0 (optimized)")
	
	return c.Do(req)
}

// GetStats returns current HTTP performance statistics
func (c *OptimizedHTTPClient) GetStats() HTTPStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// Close closes the HTTP client and cleans up resources
func (c *OptimizedHTTPClient) Close() error {
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// ResetStats resets performance statistics
func (c *OptimizedHTTPClient) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats = HTTPStats{}
}

// GetClient returns the underlying HTTP client for compatibility
func (c *OptimizedHTTPClient) GetClient() *http.Client {
	return c.client
}