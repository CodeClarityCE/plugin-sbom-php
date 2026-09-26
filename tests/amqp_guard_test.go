package main

import (
	"net"
	"os"
	"testing"
	"time"
)

// requireAMQP skips tests that run plugin.Start end to end. Start publishes to
// sbom_packageFollower, and the AMQP helper panics (taking down the whole test
// binary) when no broker is reachable, as in CI. Host and port defaults mirror
// utility-amqp-helper's buildURL.
func requireAMQP(t *testing.T) {
	t.Helper()
	host := os.Getenv("AMQP_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("AMQP_PORT")
	if port == "" {
		port = "5672"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		t.Skipf("AMQP broker %s unreachable: %v", net.JoinHostPort(host, port), err)
	}
	conn.Close()
}
