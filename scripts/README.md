# Version Management

This directory contains scripts for managing SF-CLI versions automatically.

## Version Script (`version.sh`)

The version management script automates the process of incrementing version numbers, committing changes, and creating git tags.

### Usage

```bash
./scripts/version.sh [patch|minor|major] [options]
```

### Version Types

- **patch**: Increment patch version (1.0.0 → 1.0.1)
- **minor**: Increment minor version (1.0.0 → 1.1.0) 
- **major**: Increment major version (1.0.0 → 2.0.0)

### Options

- `--dry-run`: Show what would be done without making changes
- `--no-push`: Don't push changes to remote repository
- `--no-tag`: Don't create git tag
- `--help, -h`: Show help message

### Examples

```bash
# Standard patch release (most common)
./scripts/version.sh patch

# Minor release with new features
./scripts/version.sh minor

# Major release with breaking changes
./scripts/version.sh major

# Test what would happen without making changes
./scripts/version.sh patch --dry-run

# Create version locally but don't push (for testing)
./scripts/version.sh patch --no-push

# Update version and commit but don't create tag
./scripts/version.sh patch --no-tag
```

### What the Script Does

1. **Validates environment**: Checks for clean git working directory and required files
2. **Updates version**: Modifies `Cargo.toml` with new version number
3. **Verifies changes**: Runs `cargo fmt`, `cargo build`, and `cargo test`
4. **Commits changes**: Creates commit with message format: `chore: bump version to X.Y.Z`
5. **Creates tag**: Creates annotated git tag with format: `vX.Y.Z`
6. **Pushes changes**: Pushes both commit and tag to remote repository

### Automatic Release Process

When a tag is pushed, the GitHub Actions release workflow automatically:

1. Builds binaries for Linux, Windows, and macOS
2. Creates a GitHub release with auto-generated release notes
3. Uploads the built binaries as release artifacts
4. Publishes to Crates.io (for tagged releases)

### Integration with CI/CD

The version script is designed to work seamlessly with the existing CI/CD workflows:

- **CI Workflow** (`.github/workflows/ci.yml`): Runs on all pushes and PRs
- **Release Workflow** (`.github/workflows/release.yml`): Triggers on tag pushes matching `v*.*.*`
- **Security Workflow** (`.github/workflows/security.yml`): Weekly security audits

### Safety Features

- **Backup and restore**: Creates backups of modified files and restores on failure
- **Verification**: Builds and tests the project after version changes
- **Clean working directory**: Requires all changes to be committed before running
- **Dry-run mode**: Test the script without making any changes
- **Error handling**: Comprehensive error checking and user-friendly messages

### Troubleshooting

#### Working directory not clean
```
❌ Working directory is not clean. Please commit or stash your changes.
```
**Solution**: Commit or stash your changes before running the version script.

#### Build or test failures
If the build or tests fail after version update, the script will exit without committing changes.
**Solution**: Fix the build or test issues and run the script again.

#### Permission errors
```
❌ Not in a git repository
```
**Solution**: Make sure you're running the script from the root of the sf-cli repository.

### Manual Recovery

If something goes wrong, you can manually recover:

1. **Reset to previous version**: 
   ```bash
   git reset --hard HEAD~1
   git tag -d v<new-version>
   ```

2. **Restore Cargo.toml** (if backup exists):
   ```bash
   mv Cargo.toml.backup Cargo.toml
   ```

### Best Practices

1. **Use patch versions** for bug fixes and small improvements
2. **Use minor versions** for new features that don't break existing functionality
3. **Use major versions** for breaking changes
4. **Always test with --dry-run** first when unsure
5. **Keep the working directory clean** before running version updates
6. **Monitor the CI/CD pipeline** after pushing tags to ensure successful releases

## Release Process

1. Make your changes and ensure all tests pass
2. Run the version script: `./scripts/version.sh patch`
3. Monitor the GitHub Actions workflows
4. Verify the release was created successfully
5. Update any external documentation or announcements

The entire process from version bump to published release is now fully automated! 🎉