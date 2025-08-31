# Contributing to Tarnished API

Thank you for your interest in contributing to the Tarnished API! This guide will help you get started with development and understand our workflow.

## 🚀 Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (version 1.86 or later)
- [Just](https://github.com/casey/just) task runner (recommended)
- [Docker](https://www.docker.com/) (for containerized development)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (for Kubernetes deployment)

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/markcoleman/tarnished-api.git
   cd tarnished-api
   ```

2. **Install development tools:**
   ```bash
   # Using just (recommended)
   just setup
   
   # Or manually
   cargo install cargo-watch cargo-audit cargo-outdated just
   ```

3. **Verify everything works:**
   ```bash
   just check-all
   ```

### Development with Dev Containers

For the most consistent development experience, use the provided dev container:

1. Open the repository in VS Code
2. When prompted, click "Reopen in Container"
3. All tools and extensions will be automatically installed

## 🛠️ Development Workflow

### Common Tasks

We use `just` as our task runner for consistency. Here are the most common commands:

```bash
# Show all available tasks
just

# Development server with auto-reload
just dev

# Run tests
just test

# Format and lint code
just fix-all

# Build the project
just build

# Run security audit
just audit
```

### Code Quality Standards

We maintain high code quality standards with automated checks:

#### Formatting
- Use `rustfmt` for consistent code formatting
- Run `just fmt` before committing
- VS Code auto-formats on save when using the provided settings

#### Linting
- All code must pass `clippy` with zero warnings
- Run `just lint` to check for issues
- Run `just lint-fix` to auto-fix issues where possible

#### Testing
- All new features must include tests
- Run `just test` to run the full test suite
- Integration tests are in the `tests/` directory
- Unit tests are co-located with the code they test

### Making Changes

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Write code following our style guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Verify your changes:**
   ```bash
   just check-all  # Runs format check, lint, and tests
   ```

4. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and create a PR:**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Examples:
```
feat: add rate limiting middleware
fix: resolve memory leak in weather service
docs: update API documentation
test: add integration tests for auth endpoints
```

## 🏗️ Project Structure

Understanding the codebase structure will help you contribute effectively:

```
src/
├── lib.rs                 # Main library with module exports
├── main.rs                # Application entry point
├── config/                # Configuration management
├── handlers/              # HTTP request handlers
├── middleware/            # Custom middleware
├── models/                # Data structures and schemas
├── services/              # Business logic services
└── utils/                 # Utility functions

tests/                     # Integration tests
examples/                  # Usage examples
k8s/                      # Kubernetes manifests
scripts/                  # Deployment and utility scripts
```

## 🔒 Security Considerations

- Never commit secrets or sensitive data
- All authentication events are logged for audit purposes
- HMAC signatures are required for sensitive endpoints in production
- Follow secure coding practices

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. **Description:** Clear description of the issue
2. **Steps to reproduce:** Detailed steps to reproduce the bug
3. **Expected behavior:** What you expected to happen
4. **Actual behavior:** What actually happened
5. **Environment:** OS, Rust version, etc.
6. **Logs:** Relevant log output or error messages

## 💡 Suggesting Features

Feature suggestions are welcome! Please:

1. Check if the feature already exists or is planned
2. Open an issue with the `enhancement` label
3. Provide a clear description of the feature and its benefits
4. Include example usage if applicable

## 🧪 Testing Guidelines

### Unit Tests
- Test individual functions and modules
- Use descriptive test names: `test_function_name_scenario_expected_result`
- Mock external dependencies where appropriate

### Integration Tests
- Test complete workflows and API endpoints
- Use realistic test data
- Test both success and error scenarios

### Running Tests
```bash
# All tests
just test

# Verbose output
just test-verbose

# Integration tests only
just test-integration

# Specific test
cargo test test_name
```

## 📚 Documentation

- Update documentation when adding new features
- Use clear, concise language
- Include code examples where helpful
- Document environment variables and configuration options

## 🤝 Getting Help

- Check the [README](README.md) for basic information
- Look at existing code for patterns and examples
- Review tests for usage examples
- Open an issue for questions or clarification

## 📋 Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] Code follows the project's style guidelines
- [ ] All tests pass: `just test`
- [ ] Code is properly formatted: `just fmt`
- [ ] No clippy warnings: `just lint`
- [ ] Documentation is updated if needed
- [ ] Commit messages follow the conventional format
- [ ] Security considerations have been addressed

## 🎉 Recognition

Contributors are recognized in our project documentation. Thank you for helping make Tarnished API better!

---

*For more detailed information about specific components, refer to the inline documentation and module-level README files.*