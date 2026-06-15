# Changelog

[![SemVer 2.0.0][📌semver-img]][📌semver] [![Keep-A-Changelog 1.0.0][📗keep-changelog-img]][📗keep-changelog]

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][📗keep-changelog],
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and [yes][📌major-versions-not-sacred], platform and engine support are part of the [public API][📌semver-breaking].
Please file a bug if you notice a violation of semantic versioning.

[📌semver]: https://semver.org/spec/v2.0.0.html
[📌semver-img]: https://img.shields.io/badge/semver-2.0.0-FFDD67.svg?style=flat
[📌semver-breaking]: https://github.com/semver/semver/issues/716#issuecomment-869336139
[📌major-versions-not-sacred]: https://tom.preston-werner.com/2022/05/23/major-version-numbers-are-not-sacred.html
[📗keep-changelog]: https://keepachangelog.com/en/1.0.0/
[📗keep-changelog-img]: https://img.shields.io/badge/keep--a--changelog-1.0.0-FFDD67.svg?style=flat

## [Unreleased]

### Added

### Changed

- Retemplated generated project metadata, support documentation, CI workflows,
  binstubs, and development dependency floors with the current `kettle-jem`
  template.

### Deprecated

### Removed

### Fixed

- Restored `docs/CNAME` so the generated documentation site keeps its custom domain.

### Security

## [3.0.0] - 2026-05-21

- TAG: [v3.0.0][3.0.0t]
- COVERAGE: 97.52% -- 315/323 lines in 6 files
- BRANCH COVERAGE: 79.41% -- 108/136 branches in 6 files
- 94.59% documented

### Added

- Add `auth-sanitizer` runtime dependency to redact sensitive LDAP adaptor inspection output without defining top-level `Auth` or `AuthSanitizer`

### Changed

- Minimum supported Ruby version is now 2.2.0

### Removed

- Remove deprecated (since `v2.1.0-gl` in 2018) top-level `:ca_file` and `:ssl_version` LDAP configuration options; use `:tls_options` instead
- Remove adaptor backward-compatibility that translated top-level `:ca_file` and `:ssl_version` into TLS options
- Remove deprecated direct-option specs for top-level `:ca_file` and `:ssl_version`

## [2.3.4] - 2026-05-18

- TAG: [v2.3.4][2.3.4t]
- COVERAGE: 97.44% -- 304/312 lines in 4 files
- BRANCH COVERAGE: 79.58% -- 113/142 branches in 4 files
- 94.44% documented

### Added

- Add `header_auth_source` to require explicit selection of trusted header identity source (`:env` or `:http_header`)
- Add `header_auth_require_tls` to require TLS for trusted header SSO by default
- Log a prominent security warning when `header_auth` is enabled

### Changed

- Trusted header SSO now defaults to trusting only server-set env variables and no longer checks Rack `HTTP_` header variants unless `header_auth_source: :http_header` is configured

### Fixed

- Fix OpenSSL 3/Ruby 4 compatibility in the TLS options adaptor spec

### Security

- Harden trusted header SSO against spoofing by removing automatic fallback from `REMOTE_USER` to `HTTP_REMOTE_USER`

## [2.3.3] - 2025-11-10

- TAG: [v2.3.3][2.3.3t]
- COVERAGE: 97.61% -- 286/293 lines in 4 files
- BRANCH COVERAGE: 79.69% -- 102/128 branches in 4 files
- 94.44% documented

### Added

- Documentation cleanup & updates
- YARD documentation covering 94% of the code

### Changed

- kettle-dev v1.1.54

## [2.3.2] - 2025-11-06

- TAG: [v2.3.2][2.3.2t]
- COVERAGE: 97.64% -- 290/297 lines in 4 files
- BRANCH COVERAGE: 79.69% -- 102/128 branches in 4 files
- 44.12% documented

### Added

- Support for SCRIPT_NAME for proper URL generation
  - behind certain proxies/load balancers, or
  - under a subdirectory
- Password Policy for LDAP Directories
  - password_policy: true|false (default: false)
  - on authentication failure, if the server returns password policy controls, the info will be included in the failure message
  - https://datatracker.ietf.org/doc/html/draft-behera-ldap-password-policy-11
- Support for JSON bodies
- Support custom LDAP attributes mapping
- Documentation of TLS verification options

### Changed

- Make support for OmniAuth v1.2+ explicit
  - Versions < 1.2 do not support SCRIPT_NAME properly, and may cause other issues
- Raise a distinct error when LDAP server is unreachable
    - Previously raised an invalid credentials authentication failure error, which is technically incorrect

## [2.3.1] - 2025-11-05

- TAG: [v2.3.1][2.3.1t]
- COVERAGE: 97.85% -- 228/233 lines in 4 files
- BRANCH COVERAGE: 81.58% -- 62/76 branches in 4 files
- 37.50% documented

### Added

- Added RBS types
- Upgraded RSpec tests to v3 syntax
- Improved code coverage to 98% lines and 78% branches
- Added integration tests with a complete Roda-based demo app for specs
- Well tested support for all versions of OmniAuth >= v1 and Rack >= v1 via appraisals
- Document why auth.uid == dn
- Support for LDAP-based SSO identity via HTTP Header
- Document how to use filter option
- All fixes and updates from the GitLab fork since up to v2.3.0
    - https://github.com/omniauth/omniauth-ldap/pull/100
    - https://gitlab.com/gitlab-org/gitlab-ce/issues/13280

### Changed

- Make support for Ruby v2.0 explicit
- Make support for OmniAuth v1+ explicit
- Make support for Rack v1+ explicit
- Modernize codebase to use more recent Ruby syntax (upgrade from Ruby v1 to v2 syntax) and conventions

### Fixed

- Prevent key duplication in symbolize_hash_keys

## [2.3.0-gl] (gitlab fork) - 2025-08-20

- TAG: [v2.3.0][2.3.0t-gl] (gitlab)

## [2.2.0-gl] (gitlab fork) - 2022-06-24

- TAG: [v2.2.0][2.2.0t-gl] (gitlab)

## [2.1.1-gl] (gitlab fork) - 2019-02-22

- TAG: [v2.1.1][2.1.1t-gl] (gitlab)

### Added

- Add a String check to `tls_options` sanitization to allow other objects

## [2.1.0-gl] (gitlab fork) - 2018-06-18

- TAG: [v2.1.0][2.1.0t-gl] (gitlab)

### Added

- Expose `:tls_options` SSL configuration option.

### Deprecated

- Deprecate :ca_file, :ssl_version

## [2.0.4-gl] (gitlab fork) - 2017-08-10

- TAG: [v2.0.4][2.0.4t-gl] (gitlab)

- Improve log message when invalid credentials are used

## 2.0.3 (gitlab fork) - 2017-07-20

- Protects against wrong request method call to callback

## [2.0.2-gl] (gitlab fork) - 2017-06-13

- TAG: [v2.0.2][2.0.2t-gl] (gitlab)

## [2.0.1-gl] (gitlab fork) - 2017-06-09

- TAG: [v2.0.1][2.0.1t-gl] (gitlab)

## [2.0.0-gl] (gitlab fork) - 2017-06-07

- TAG: [v2.0.0][2.0.0t-gl] (gitlab)

## [2.0.0] (intridea) - 2018-01-09

- TAG: [v2.0.0][2.0.0t] (github)

## [1.2.1-gl] (gitlab fork) - 2015-03-17

- TAG: [v1.2.1][1.2.1t-gl] (gitlab)

## [1.2.0-gl] (gitlab fork) - 2014-10-29

- TAG: [v1.2.0][1.2.0t-gl] (gitlab)

## [1.1.0-gl] (gitlab fork) - 2014-09-08

- TAG: [v1.1.0][1.1.0t-gl] (gitlab)

## [1.0.5-gl] - 2016-02-17

- TAG: [v1.0.5][1.0.5t-gl] (gitlab fork, gem not released)
- TAG: [v1.0.5][1.0.5t] (github)

## 1.0.4

- released 2014-02-03 (intridea)
- released 2013-11-13 (gitlab fork)

## 1.0.3

- released 2013-01-23 (intridea)
- released 2013-06-13 (gitlab fork)

## [1.0.2-gl]

- TAG: [v1.0.2][1.0.2t-gl] (gitlab) - released 2012-12-30
- TAG: [v1.0.2][1.0.2t] (github) - released 2011-12-17

## 1.0.1 - 2011-11-02

## [1.0.0-gl] - 2011-11-02

- TAG: [v1.0.0][1.0.0t-gl] (gitlab)
- TAG: [v1.0.0][1.0.0t] (github)

[2.3.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.2.0...v2.3.0
[2.3.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.3.0
[2.2.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.1.1...v2.2.0
[2.2.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.2.0
[2.1.1-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.1.0...v2.1.1
[2.1.1t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.1.1
[2.1.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.0.4...v2.1.0
[2.1.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.1.0
[2.0.4-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.0.2...v2.0.4
[2.0.4t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.0.4
[//]: # ( There is no tag for v2.0.3 on GitLab)
[2.0.2-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.0.1...v2.0.2
[2.0.2t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.0.2
[2.0.1-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v2.0.0...v2.0.1
[2.0.1t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.0.1
[2.0.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v1.2.1...v2.0.0
[2.0.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/2.0.0
[2.0.0]: https://github.com/omniauth/omniauth-ldap/compare/v1.0.5...v2.0.0
[2.0.0t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v2.0.0
[1.2.1-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v1.2.0...v1.2.1
[1.2.1t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/1.2.1
[1.2.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v1.1.0...v1.2.0
[1.2.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/1.2.0
[1.1.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v1.0.2...v1.1.0
[1.1.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/1.1.0
[1.0.5-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v1.0.2...v1.0.5
[1.0.5t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/1.0.5
[1.0.5]: https://github.com/omniauth/omniauth-ldap/compare/v1.0.2...v1.0.5
[1.0.5t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v1.0.5
[//]: # ( There are no tags for v1.0.3, v1.0.4 on GitHub, or GitLab)
[1.0.2-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/v1.0.1...v1.0.2
[1.0.2t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/1.0.2
[1.0.2]: https://github.com/omniauth/omniauth-ldap/compare/v1.0.1...v1.0.2
[1.0.2t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v1.0.2
[//]: # ( There are no tags for v1.0.1 on GitHub, or GitLab)
[1.0.0-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/compare/5656da80d4193e0d0584f44bac493a87695e580f...v1.0.0
[1.0.0t-gl]: https://gitlab.com/gitlab-org/ruby/gems/omniauth-ldap/-/tags/1.0.0
[1.0.0]: https://github.com/omniauth/omniauth-ldap/compare/5656da80d4193e0d0584f44bac493a87695e580f...v1.0.0
[1.0.0t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v1.0.0

[Unreleased]: https://github.com/omniauth/omniauth-ldap/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/omniauth/omniauth-ldap/compare/v2.3.4...v3.0.0
[3.0.0t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v3.0.0
[2.3.4]: https://github.com/omniauth/omniauth-ldap/compare/v2.3.3...v2.3.4
[2.3.4t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v2.3.4
[2.3.3]: https://github.com/omniauth/omniauth-ldap/compare/v2.3.2...v2.3.3
[2.3.3t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v2.3.3
[2.3.2]: https://github.com/omniauth/omniauth-ldap/compare/v2.3.1...v2.3.2
[2.3.2t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v2.3.2
[2.3.1]: https://github.com/omniauth/omniauth-ldap/compare/v2.0.0...v2.3.1
[2.3.1t]: https://github.com/omniauth/omniauth-ldap/releases/tag/v2.3.1
