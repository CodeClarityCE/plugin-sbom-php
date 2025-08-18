# Artifact Repository Support

This module provides comprehensive artifact repository support for PHP Composer projects. Artifact repositories allow distributing packages as ZIP archives, which is useful for private packages, legacy distributions, or specialized deployment scenarios.

## Overview

The artifact resolver handles three main types of artifact repositories:

1. **Single ZIP Files** - Direct links to ZIP archives containing packages
2. **URL Pattern Repositories** - Template URLs with placeholders for package names/versions
3. **Directory-based Repositories** - Directory listings containing multiple ZIP files

## Architecture

### Core Components

- **ArtifactResolver** - Main resolver class handling all artifact operations
- **Artifact Discovery** - Locates and identifies available packages
- **Download Management** - Handles ZIP file downloading with caching
- **Package Extraction** - Extracts and parses composer.json from ZIP archives
- **Authentication Integration** - Supports various authentication methods

### Integration Points

- **Private Package Resolver** - Integrates with existing private repository system
- **Enhanced Composer Parser** - Automatic setup and configuration
- **Authentication Manager** - Uses existing credential management
- **Caching System** - Efficient artifact caching and reuse

## Supported Repository Types

### 1. Single ZIP File

Direct URL pointing to a ZIP archive containing a Composer package.

**Configuration Example:**
```json
{
    "repositories": [
        {
            "type": "artifact",
            "url": "https://repo.company.com/packages/acme-library-1.0.0.zip"
        }
    ]
}
```

**Features:**
- Direct ZIP file download
- Automatic composer.json extraction
- Package validation
- Authentication support

### 2. URL Pattern Repository

Template URLs with placeholders that are replaced with package information.

**Configuration Example:**
```json
{
    "repositories": [
        {
            "type": "artifact", 
            "url": "https://repo.company.com/packages/{vendor}/{package}/{version}.zip"
        }
    ]
}
```

**Supported Placeholders:**
- `{name}` - Full package name (vendor/package)
- `{vendor}` - Vendor part of package name
- `{package}` - Package part of package name
- `{version}` - Package version

**Features:**
- Automatic URL generation
- Multiple version discovery
- Fallback version patterns
- URL existence validation

### 3. Directory-based Repository (Future)

Directory listings containing multiple ZIP files with automatic discovery.

**Configuration Example:**
```json
{
    "repositories": [
        {
            "type": "artifact",
            "url": "https://repo.company.com/packages/"
        }
    ]
}
```

**Note:** Currently not implemented - requires HTTP directory listing support.

## Authentication

The artifact resolver supports all authentication methods available in the private repository system:

### HTTP Basic Authentication
```json
{
    "http-basic": {
        "repo.company.com": {
            "username": "user",
            "password": "pass"
        }
    }
}
```

### Bearer Token Authentication
```json
{
    "bearer": {
        "repo.company.com": "your-bearer-token"
    }
}
```

### GitHub Token Authentication
```json
{
    "github-oauth": {
        "github.company.com": "your-github-token"
    }
}
```

### GitLab Token Authentication
```json
{
    "gitlab-token": {
        "gitlab.company.com": "your-gitlab-token"
    }
}
```

## Caching System

### Cache Behavior
- **Location**: `${TEMP}/php-sbom-artifact-cache/`
- **Scope**: Per-artifact caching based on URL and version
- **Persistence**: Cache persists across runs until manual cleanup
- **Size Management**: No automatic size limits (manual cleanup required)

### Cache Structure
```
php-sbom-artifact-cache/
├── vendor-package-1.0.0.zip
├── acme-library-2.1.0.zip
└── company-framework-latest.zip
```

### Cache Benefits
- **Performance**: Avoid re-downloading large ZIP files
- **Reliability**: Offline access to previously downloaded artifacts
- **Bandwidth**: Reduce network usage for repeated builds
- **Speed**: Fast package resolution for cached artifacts

## Package Discovery Process

### 1. Repository Type Detection
```go
func (ar *ArtifactResolver) discoverArtifacts(repo, packageName) {
    if ar.isDirectoryRepository(repo.URL) {
        return ar.discoverDirectoryArtifacts(repo, packageName)
    }
    if ar.isURLPatternRepository(repo.URL) {
        return ar.discoverURLPatternArtifacts(repo, packageName)
    }
    if ar.isZipFile(repo.URL) {
        // Single ZIP file
        return []*ArtifactInfo{{URL: repo.URL}}
    }
}
```

### 2. Version Resolution
For URL pattern repositories, the resolver tries common version patterns:
- Exact version matches
- Semantic version patterns (1.0.0, 2.0, etc.)
- Special versions (latest, master, main)
- Development versions (dev-main, dev-develop)

### 3. URL Validation
Before attempting download, the resolver validates URL existence:
```go
func (ar *ArtifactResolver) urlExists(url string) bool {
    req, _ := http.NewRequest("HEAD", url, nil)
    ar.addAuthentication(req, url)
    resp, err := ar.httpClient.Do(req)
    return err == nil && resp.StatusCode == 200
}
```

## Package Extraction Process

### 1. ZIP Download
```go
func (ar *ArtifactResolver) downloadArtifact(repo, artifact) error {
    // Check cache first
    if cached {
        return nil
    }
    
    // Download with authentication
    req := http.NewRequest("GET", artifact.URL, nil)
    ar.addAuthentication(req, artifact.URL)
    
    // Save to cache
    io.Copy(cacheFile, response.Body)
}
```

### 2. ZIP Extraction
```go
func (ar *ArtifactResolver) extractZipFile(zipPath, destDir) error {
    reader, _ := zip.OpenReader(zipPath)
    
    for _, file := range reader.File {
        // Security: Prevent zip slip attacks
        if !strings.HasPrefix(path, destDir) {
            return fmt.Errorf("invalid file path")
        }
        
        // Extract file...
    }
}
```

### 3. composer.json Discovery
```go
func (ar *ArtifactResolver) findComposerJSON(baseDir) (string, error) {
    filepath.Walk(baseDir, func(path, info, err) error {
        if info.Name() == "composer.json" {
            composerPath = path
            return filepath.SkipDir // Stop after first match
        }
    })
}
```

## Security Considerations

### ZIP Slip Protection
The resolver includes protection against ZIP slip attacks:
```go
// Security check: prevent zip slip attacks
if !strings.HasPrefix(path, filepath.Clean(destDir)+string(os.PathSeparator)) {
    return fmt.Errorf("invalid file path in ZIP: %s", file.Name)
}
```

### Credential Security
- **Never Logged**: Authentication credentials are never logged
- **Memory Only**: Credentials stored in memory during processing
- **Request Scoped**: Authentication applied per-request
- **Secure Cleanup**: Temporary files cleaned up automatically

### File System Security
- **Controlled Extraction**: ZIP extraction to controlled directory
- **Path Validation**: All file paths validated before extraction
- **Permission Control**: Extracted files use appropriate permissions
- **Cleanup**: Automatic cleanup of temporary directories

## Error Handling

### Download Errors
```go
// Network timeouts (120 seconds for large files)
httpClient := &http.Client{
    Timeout: 120 * time.Second,
}

// Authentication errors
if resp.StatusCode == 401 || resp.StatusCode == 403 {
    return fmt.Errorf("authentication failed for artifact")
}

// File not found
if resp.StatusCode == 404 {
    return fmt.Errorf("artifact not found: %s", url)
}
```

### Extraction Errors
```go
// Corrupted ZIP files
if err := zip.OpenReader(zipPath); err != nil {
    return fmt.Errorf("corrupted ZIP file: %w", err)
}

// Missing composer.json
if composerPath == "" {
    return fmt.Errorf("composer.json not found in artifact")
}

// Invalid composer.json
if err := json.Unmarshal(content, &composerData); err != nil {
    return fmt.Errorf("invalid composer.json: %w", err)
}
```

### Graceful Degradation
- **Partial Failures**: Continue processing other repositories
- **Network Issues**: Retry with exponential backoff
- **Cache Corruption**: Re-download if cache is corrupted
- **Missing Packages**: Return nil without failing entire resolution

## Performance Optimization

### Caching Strategy
- **Local Cache**: Avoid re-downloading artifacts
- **HEAD Requests**: Check existence before download
- **Parallel Processing**: Multiple artifact discovery in parallel
- **Memory Efficient**: Stream large ZIP files during extraction

### Network Optimization
- **Timeout Management**: Appropriate timeouts for large files
- **Connection Reuse**: HTTP client with connection pooling
- **Compression**: Support for compressed transfers
- **Range Requests**: Future support for partial downloads

### Storage Optimization
- **Efficient Extraction**: Extract only necessary files
- **Temporary Cleanup**: Automatic cleanup of extracted files
- **Cache Management**: LRU-style cache eviction (future)
- **Disk Space**: Monitor and warn about disk usage

## Usage Examples

### Basic Configuration
```json
{
    "repositories": [
        {
            "type": "artifact",
            "url": "https://packages.company.com/{vendor}-{package}-{version}.zip"
        }
    ]
}
```

### Advanced Configuration with Authentication
```json
{
    "repositories": [
        {
            "type": "artifact",
            "url": "https://secure-repo.company.com/artifacts/{name}/{version}.zip",
            "options": {
                "http": {
                    "header": ["X-Custom-Header: value"]
                }
            }
        }
    ],
    "config": {
        "http-basic": {
            "secure-repo.company.com": {
                "username": "artifacts-user",
                "password": "secure-password"
            }
        }
    }
}
```

### Multiple Artifact Sources
```json
{
    "repositories": [
        {
            "type": "artifact",
            "url": "https://primary-artifacts.company.com/{name}-{version}.zip"
        },
        {
            "type": "artifact", 
            "url": "https://backup-artifacts.company.com/packages/{vendor}/{package}/{version}.zip"
        },
        {
            "type": "artifact",
            "url": "https://legacy-packages.company.com/archive.zip"
        }
    ]
}
```

## Integration with SBOM Generation

### Enhanced SBOM Output
When artifact repositories are used, the enhanced SBOM includes:

```json
{
    "packages": [
        {
            "name": "company/private-package",
            "version": "1.0.0",
            "is_private": true,
            "source_repository": "https://artifacts.company.com/company-private-package-1.0.0.zip",
            "repository_type": "artifact",
            "authentication_used": true
        }
    ],
    "private_repositories": [
        {
            "type": "artifact",
            "url": "https://artifacts.company.com/{name}-{version}.zip"
        }
    ],
    "authentication_info": [
        {
            "host": "artifacts.company.com",
            "auth_type": "http-basic",
            "success": true,
            "repository": "https://artifacts.company.com/company-private-package-1.0.0.zip"
        }
    ]
}
```

### Private Package Vulnerability Analysis
Artifact packages are automatically included in private package vulnerability analysis:

- **Pattern Detection**: Scans package names for problematic patterns
- **License Compliance**: Validates license information from composer.json
- **Security Policy**: Enforces organizational security policies
- **Supply Chain Risk**: Analyzes dependency complexity

## Troubleshooting

### Common Issues

**1. Artifact not found (404 errors)**
```bash
# Check URL pattern configuration
# Verify package name format (vendor/package vs vendor-package)
# Confirm version format in URL pattern
```

**2. Authentication failures (401/403 errors)**
```bash
# Verify credentials in auth.json or environment variables
# Check authentication method matches repository requirements
# Confirm host matching in authentication configuration
```

**3. ZIP extraction failures**
```bash
# Check ZIP file integrity
# Verify disk space for extraction
# Confirm file permissions in cache directory
```

**4. Missing composer.json in artifact**
```bash
# Verify ZIP contains composer.json in root or subdirectory
# Check ZIP file structure matches expected format
# Confirm package was properly packaged as Composer artifact
```

### Debug Logging
```bash
export ARTIFACT_RESOLVER_DEBUG=true
export PRIVATE_REPOS_DEBUG=true
```

### Cache Management
```bash
# Clear artifact cache
rm -rf $(php -r "echo sys_get_temp_dir();")/php-sbom-artifact-cache

# Check cache usage
du -sh $(php -r "echo sys_get_temp_dir();")/php-sbom-artifact-cache
```

## Future Enhancements

### Planned Features
1. **Directory Repository Support** - HTTP directory listing parsing
2. **Parallel Downloads** - Concurrent artifact downloading
3. **Delta Updates** - Incremental artifact updates
4. **Signature Verification** - Artifact integrity verification
5. **Cache Management** - Automatic cache size management

### Advanced Features
1. **Custom Extractors** - Support for other archive formats
2. **Streaming Extraction** - Memory-efficient large archive handling
3. **Metadata Caching** - Cache composer.json metadata separately
4. **Background Downloads** - Pre-fetch popular artifacts
5. **Mirror Support** - Fallback to mirror repositories

## Related Documentation

- [Private Repository Implementation](../private_repos/README.md)
- [VCS Repository Support](../vcs/README.md)
- [PHP SBOM Generation](../README.md)
- [Authentication Guide](../auth/README.md)