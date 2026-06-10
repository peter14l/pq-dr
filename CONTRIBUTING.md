# Contributing to PQ-Aura

Thank you for your interest in contributing to PQ-Aura! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.70.0 or later
- cargo-fuzz (for fuzz testing)
- cargo-deny (for dependency auditing)

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/peter14l/pq-dr.git
cd pq-dr

# Install development tools
cargo install cargo-fuzz
cargo install cargo-deny
cargo install cargo-audit

# Run tests
cargo test --all

# Run benchmarks
cargo bench
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

- Follow Rust best practices
- Add tests for new functionality
- Update documentation as needed

### 3. Run Quality Checks

```bash
# Run all tests
cargo test --all

# Run Clippy
cargo clippy --all -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Run security audit
cargo audit
cargo deny check
```

### 4. Submit a Pull Request

- Write a clear PR description
- Reference any related issues
- Ensure all CI checks pass

## Code Style

### Rust Style Guide

- Follow the Rust API Guidelines
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Write comprehensive documentation

### Naming Conventions

- Types: `PascalCase`
- Functions: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Modules: `snake_case`

### Documentation

- All public items must have documentation
- Include examples in documentation
- Document safety guarantees
- Document performance characteristics

## Testing

### Unit Tests

- Test all public functions
- Test edge cases
- Test error conditions
- Use property-based testing where appropriate

### Integration Tests

- Test full protocol flows
- Test cross-platform compatibility
- Test backward compatibility

### Fuzz Testing

- Add fuzz targets for new parsing functions
- Run fuzz tests regularly
- Report any crashes immediately

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead, please email security@[oasis-project].com with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Review

All changes to cryptographic code require security review before merging.

## License

By contributing to PQ-Aura, you agree that your contributions will be licensed under the GNU General Public License v3.0.

## Questions?

If you have questions, please open a discussion or contact the maintainers.
