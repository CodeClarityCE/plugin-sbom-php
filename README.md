<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)

<details open="open">
<summary>Table of Contents</summary>

- [CodeClarity Plugin - PHP SBOM](#codeclarity-plugin---php-sbom)
  - [Contributing](#contributing)
  - [Reporting Issues](#reporting-issues)
  - [Purpose](#purpose)
  - [Current Features](#current-features)
  - [Future Features](#future-features)
  - [Dev Usage](#dev-usage)


</details>

---

# CodeClarity Plugin - PHP SBOM

## Contributing

If you'd like to contribute code or documentation, please see [CONTRIBUTING.md](https://github.com/CodeClarityCE/codeclarity-dev/blob/main/CONTRIBUTING.md) for guidelines on how to do so.

## Reporting Issues

Please report any issues with the setup process or other problems encountered while using this repository by opening a new issue in this project's GitHub page.

## Purpose

The PHP SBOM (Software Bill of Materials) service creates an inventory of dependencies for PHP applications using Composer.

<br> It is the first stage of the Software Composition Analysis process for PHP projects.

1. Identify dependencies (SBOM)
2. Identify known vulnerabile dependencies
3. Identify licenses & license compliance
4. Compute and verify upgrades to the application

<br>

## Current Features

1. **Composer Integration**: Full support for `composer.json` and `composer.lock` parsing
2. **Framework Detection**: Automatic detection of popular PHP frameworks (Laravel, Symfony, WordPress, etc.)
3. **Extension Analysis**: PHP extension dependency tracking from composer.json requirements
4. **PHAR Support**: Analysis of PHAR archives for embedded dependencies
5. **Monorepo Support**: Multi-workspace PHP project analysis

### Supported PHP Frameworks

| Framework | Detection Method | Status |
|-----------|------------------|---------
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

<br>

## Future Features

1. Support for additional PHP package managers (PEAR, PECL)
2. Enhanced PHAR analysis with dependency extraction
3. Private Composer repository support

<br>

## Dev Usage

To execute this service for development purposes, the following parameter is required:

```
Usage of php-sbom:
  -source-code-directory string
    	Absolute Path to the source code directory (Required)
```

The service will output SBOM data to stdout in JSON format.

<br>