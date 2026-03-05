# Changelog

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* Now producing wheels for Python 3.14, PyPy 3.11.

### Changed

* EAD items have a custom `__repr__`.
* Fixed package metadata.
* Updated underlying pyo3 to 0.28.
* Refactoring in the underlying lakers crate.

### Removed

* No longer producing wheels for PyPy 3.10 (as it became unsupported in PyO3).
