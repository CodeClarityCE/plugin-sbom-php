package main

import (
	"log"
	
	"github.com/CodeClarityCE/plugin-php-sbom/src"
	"github.com/CodeClarityCE/utility-types/boilerplates"
)

// main is the entry point for the PHP SBOM plugin
func main() {
	// Create the PHP SBOM analyzer
	analyzer := &src.PHPSBOMAnalyzer{}
	
	// Create and start the plugin using the generic SBOM plugin base
	err := boilerplates.CreateSBOMPlugin(analyzer)
	if err != nil {
		log.Fatalf("PHP SBOM Plugin failed: %v", err)
	}
}