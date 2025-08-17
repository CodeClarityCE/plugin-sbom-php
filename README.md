# PHP SBOM Plugin

<br>

<div align="center">
    <img src="https://user-images.githubusercontent.com/124595411/233356880-fdc7ea8a-8b1d-4991-8726-67b47e91df9e.svg" width="400px" />
</div>

<br>

## Purpose

The PHP SBOM (Software Bill of Materials) plugin generates comprehensive dependency inventories for PHP projects using Composer.

## Features

- **Composer Integration**: Full support for `composer.json` and `composer.lock` parsing
- **Framework Detection**: Automatic detection of popular PHP frameworks via composer dependencies
- **Extension Analysis**: PHP extension dependency tracking from composer.json requirements
- **PHAR Support**: Analysis of PHAR archives for embedded dependencies
- **Monorepo Support**: Multi-workspace PHP project analysis

## Supported PHP Frameworks

Framework detection is based on composer.json dependencies:

| Framework | Detection Method | Status |
|-----------|------------------|---------|
| Laravel | `laravel/framework` dependency | ✅ Implemented |
| Symfony | `symfony/framework-bundle` or `symfony/*` packages | ✅ Implemented |
| WordPress | `wordpress-plugin`/`wordpress-theme` type or `johnpbloch/wordpress` | ✅ Implemented |
| Drupal | `drupal/core` dependency or `drupal-*` type | ✅ Implemented |
| CakePHP | `cakephp/cakephp` dependency | ✅ Implemented |
| CodeIgniter | `codeigniter4/framework` dependency | ✅ Implemented |
| Slim | `slim/slim` dependency | ✅ Implemented |
| Yii2 | `yiisoft/yii2` dependency | ✅ Implemented |
| Lumen | `laravel/lumen-framework` dependency | ✅ Implemented |
| Laminas/Zend | `laminas/laminas-mvc` or `zendframework/zend-mvc` | ✅ Implemented |

## Extension Detection

PHP extensions are detected from:

1. **Composer Requirements** (Primary method):
   ```json
   {
     "require": {
       "ext-openssl": "*",
       "ext-curl": "*", 
       "ext-json": "*",
       "ext-pdo": "*"
     }
   }
   ```

2. **PHP Binary Detection** (Fallback - requires PHP binary in PATH):
   ```bash
   php -m  # List loaded modules
   php -v  # Get PHP version
   ```

## Configuration

```json
{
    "name": "php-sbom",
    "version": "1.0.0",
    "stage": 2,
    "languages": ["PHP"],
    "description": "PHP Software Bill of Materials generator"
}
```

## Quick Start

```bash
# Build the plugin
make build

# Run analysis on a PHP project
echo '{"source_code_dir": "/path/to/php/project"}' | ./main

# Run tests
go test ./tests/
```

## Output Format

The plugin generates SBOM data compatible with the unified analysis pipeline:

```json
{
  "analysis_id": "uuid-here",
  "language": "PHP",
  "framework": "Laravel",
  "packages": [
    {
      "name": "laravel/framework",
      "version": "9.52.0",
      "type": "library",
      "license": ["MIT"],
      "purl": "pkg:composer/laravel/framework@9.52.0"
    }
  ],
  "extensions": [
    {
      "name": "openssl",
      "version": "*",
      "type": "external",
      "status": "required"
    }
  ]
}
```

## Testing

Available test projects:

```bash
# Test with different project types
ls tests/test*/

# Run specific tests
go test ./tests/ -run TestFrameworkDetection
go test ./tests/ -run TestComposerParsing
go test ./tests/ -run TestExtensionDetection
```

## Troubleshooting

### Common Issues

**SBOM Generation Fails**:
```bash
# Check composer files exist
ls -la composer.json composer.lock

# Test parsing manually
cd tests/test1 && go run ../../main.go
```

**Framework Not Detected**:
- Check if framework-specific dependencies are listed in composer.json
- Verify the framework is in the supported list above

**Extensions Not Found**:
```bash
# Check composer.json for extension requirements
grep "ext-" composer.json

# Verify PHP binary is in PATH (for fallback detection)
which php
```

## Limitations

- **PHP Binary**: Extension detection falls back to `php` binary if available, but primarily relies on composer.json
- **Package Database**: PHP package version information requires populated knowledge database
- **Private Repositories**: Currently only supports public Composer packages

## Integration

This plugin integrates with:

- **vuln-finder**: Provides SBOM data for vulnerability analysis
- **license-finder**: Provides dependency info for license compliance
- **knowledge service**: Uses package and vulnerability databases
