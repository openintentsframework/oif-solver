# Contributing Guide

Thank you for your interest in contributing to the OIF Solver! This guide will help you get started with development, understand our standards, and submit contributions effectively.

## Getting Started

### Prerequisites

Ensure you have the following tools installed:

- **Rust** (stable toolchain) - [Install Rust](https://rustup.rs/)
- **Git** for version control
- **Foundry** (for testing) - [Install Foundry](https://book.getfoundry.sh/)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/oif-solver.git
cd oif-solver
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/openintentsframework/oif-solver.git
```

### Development Setup

1. **Build the project**:

```bash
cargo build
```

2. **Run tests**:

```bash
cargo test
```

3. **Set up demo environment**:

```bash
./oif-demo env up
```

4. **Verify everything works**:

```bash
cargo run --bin solver -- --config config/demo.toml
```

## Development Workflow

### Branch Strategy

- **main**: Stable release branch
- **develop**: Integration branch for new features
- **feature/**: Feature branches (e.g., `feature/new-protocol`)
- **fix/**: Bug fix branches (e.g., `fix/gas-estimation`)
- **docs/**: Documentation-only changes

### Creating a Feature Branch

```bash
# Update your local main branch
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feature/your-feature-name
```

### Staying Up-to-Date

Regularly sync your fork with upstream:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Code Standards

### Rust Style Guidelines

We follow standard Rust conventions with some project-specific additions:

#### Formatting

Use `rustfmt` for consistent code formatting:

```bash
# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt
```

Configuration is in `rustfmt.toml`:

```toml
max_width = 100
hard_tabs = true
edition = "2021"
```

#### Linting

Use `clippy` for code quality:

```bash
# Check for issues
cargo clippy -- -D warnings

# Fix issues automatically where possible
cargo clippy --fix
```

## Testing Requirements

### Test Categories

1. **Unit Tests**: Test individual functions and methods

## Pull Request Process

### Before Submitting

1. **Run the full test suite**:

```bash
cargo test
```

2. **Check code formatting**:

```bash
cargo fmt --check
```

3. **Run linting**:

```bash
cargo clippy -- -D warnings
```

4. **Update documentation** if needed

5. **Test with demo environment**:

```bash
./oif-demo env reset && ./oif-demo env up
cargo run --bin solver -- --config config/demo.toml
./oif-demo quote test escrow permit2 A2B
```

### Pull Request Template

Use this template for your PR description:

```markdown
## Description

Brief description of changes and motivation.

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that breaks existing functionality)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Demo environment tested

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No new warnings introduced

## Community Guidelines

### Code of Conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Assume good intentions
- Respect different perspectives

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussions
- **Pull Requests**: Code review and technical discussions

### Getting Help

If you need help:

1. **Check documentation** first
2. **Search existing issues** for similar problems
3. **Ask in GitHub Discussions** for general questions
4. **Open an issue** for bugs or feature requests

## Recognition

Contributors are recognized in:

- **CONTRIBUTORS.md**: List of all contributors
- **Release Notes**: Major contributions highlighted
- **Documentation**: Author attribution where appropriate

Thank you for contributing to the OIF Solver! Your contributions help make cross-chain intent execution more reliable and accessible for everyone.
```
