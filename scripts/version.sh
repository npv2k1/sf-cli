#!/bin/bash

# Version Management Script for SF-CLI
# Automatically increment version, commit changes, create tags, and push

set -e

# Configuration
CARGO_TOML="Cargo.toml"
GIT_REMOTE="origin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Show usage information
show_usage() {
    echo "Usage: $0 [patch|minor|major] [options]"
    echo ""
    echo "Version types:"
    echo "  patch    Increment patch version (1.0.0 -> 1.0.1)"
    echo "  minor    Increment minor version (1.0.0 -> 1.1.0)"  
    echo "  major    Increment major version (1.0.0 -> 2.0.0)"
    echo ""
    echo "Options:"
    echo "  --dry-run        Show what would be done without making changes"
    echo "  --no-push        Don't push changes to remote repository"
    echo "  --no-tag         Don't create git tag"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 patch                    # Increment patch version and push"
    echo "  $0 minor --dry-run          # Show what minor increment would do"
    echo "  $0 major --no-push          # Increment major version but don't push"
    echo ""
}

# Parse command line arguments
VERSION_TYPE=""
DRY_RUN=false
NO_PUSH=false
NO_TAG=false

while [[ $# -gt 0 ]]; do
    case $1 in
        patch|minor|major)
            VERSION_TYPE="$1"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-push)
            NO_PUSH=true
            shift
            ;;
        --no-tag)
            NO_TAG=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if version type is provided
if [[ -z "$VERSION_TYPE" ]]; then
    print_error "Version type is required"
    show_usage
    exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not in a git repository"
    exit 1
fi

# Check if Cargo.toml exists
if [[ ! -f "$CARGO_TOML" ]]; then
    print_error "Cargo.toml not found in current directory"
    exit 1
fi

# Check for uncommitted changes
if [[ $(git status --porcelain | wc -l) -gt 0 ]]; then
    print_error "Working directory is not clean. Please commit or stash your changes."
    git status --short
    exit 1
fi

# Get current version from Cargo.toml
get_current_version() {
    grep '^version = ' "$CARGO_TOML" | head -n 1 | sed 's/version = "\(.*\)"/\1/'
}

# Parse version string into major.minor.patch
parse_version() {
    local version="$1"
    if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        print_error "Invalid version format: $version"
        exit 1
    fi
    
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"
}

# Increment version based on type
increment_version() {
    local type="$1"
    case "$type" in
        major)
            ((major++))
            minor=0
            patch=0
            ;;
        minor)
            ((minor++))
            patch=0
            ;;
        patch)
            ((patch++))
            ;;
    esac
    echo "${major}.${minor}.${patch}"
}

# Update version in Cargo.toml
update_cargo_version() {
    local new_version="$1"
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would update Cargo.toml version to: $new_version"
        return
    fi
    
    # Create backup
    cp "$CARGO_TOML" "${CARGO_TOML}.backup"
    
    # Update version using sed
    sed -i.tmp "s/^version = \".*\"/version = \"$new_version\"/" "$CARGO_TOML"
    rm -f "${CARGO_TOML}.tmp"
    
    print_success "Updated Cargo.toml version to: $new_version"
}

# Verify the version was updated correctly
verify_version_update() {
    local expected_version="$1"
    local actual_version=$(get_current_version)
    
    if [[ "$actual_version" != "$expected_version" ]]; then
        print_error "Version update verification failed. Expected: $expected_version, Got: $actual_version"
        # Restore backup if available
        if [[ -f "${CARGO_TOML}.backup" ]]; then
            mv "${CARGO_TOML}.backup" "$CARGO_TOML"
            print_info "Restored Cargo.toml from backup"
        fi
        exit 1
    fi
    
    # Remove backup on success
    rm -f "${CARGO_TOML}.backup"
}

# Build and test to ensure everything still works
run_verification_tests() {
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would run: cargo fmt --all && cargo build && cargo test"
        return
    fi
    
    print_info "Running cargo fmt to format code..."
    cargo fmt --all
    
    print_info "Running build to verify compilation..."
    if ! cargo build --release --quiet; then
        print_error "Build failed after version update"
        exit 1
    fi
    
    print_info "Running tests to verify functionality..."
    if ! cargo test --quiet; then
        print_error "Tests failed after version update"
        exit 1
    fi
    
    print_success "All verification tests passed"
}

# Commit changes
commit_changes() {
    local new_version="$1"
    local commit_message="chore: bump version to $new_version"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would commit with message: '$commit_message'"
        print_info "Changed files:"
        git diff --name-only
        return
    fi
    
    # Add the changed files
    git add "$CARGO_TOML" Cargo.lock
    
    # Commit with version message
    git commit -m "$commit_message"
    
    print_success "Committed changes with message: '$commit_message'"
}

# Create and push git tag
create_tag() {
    local new_version="$1"
    local tag_name="v$new_version"
    
    if [[ "$NO_TAG" == true ]]; then
        print_info "Skipping tag creation (--no-tag specified)"
        return
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would create tag: $tag_name"
        return
    fi
    
    # Create annotated tag
    git tag -a "$tag_name" -m "Release $tag_name"
    
    print_success "Created tag: $tag_name"
}

# Push changes and tags
push_changes() {
    local new_version="$1"
    local tag_name="v$new_version"
    
    if [[ "$NO_PUSH" == true ]]; then
        print_info "Skipping push (--no-push specified)"
        return
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "Would push to remote: $GIT_REMOTE"
        if [[ "$NO_TAG" != true ]]; then
            print_info "Would push tag: $tag_name"
        fi
        return
    fi
    
    # Push commits
    print_info "Pushing commits to $GIT_REMOTE..."
    git push "$GIT_REMOTE"
    
    # Push tags if not disabled
    if [[ "$NO_TAG" != true ]]; then
        print_info "Pushing tag $tag_name to $GIT_REMOTE..."
        git push "$GIT_REMOTE" "$tag_name"
    fi
    
    print_success "Successfully pushed changes to $GIT_REMOTE"
}

# Main execution
main() {
    print_info "SF-CLI Version Management Script"
    print_info "================================"
    
    # Get current version
    current_version=$(get_current_version)
    print_info "Current version: $current_version"
    
    # Parse and increment version
    parse_version "$current_version"
    new_version=$(increment_version "$VERSION_TYPE")
    
    print_info "New version: $new_version ($VERSION_TYPE increment)"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Perform operations
    echo ""
    print_info "Step 1: Updating Cargo.toml version..."
    update_cargo_version "$new_version"
    
    if [[ "$DRY_RUN" != true ]]; then
        verify_version_update "$new_version"
    fi
    
    print_info "Step 2: Running verification tests..."
    run_verification_tests
    
    print_info "Step 3: Committing changes..."
    commit_changes "$new_version"
    
    print_info "Step 4: Creating git tag..."
    create_tag "$new_version"
    
    print_info "Step 5: Pushing changes and tags..."
    push_changes "$new_version"
    
    echo ""
    print_success "🎉 Version successfully updated from $current_version to $new_version!"
    
    if [[ "$DRY_RUN" != true && "$NO_PUSH" != true ]]; then
        print_info "🚀 The release workflow will automatically trigger and create a GitHub release."
        print_info "📦 Binaries will be built for Linux, Windows, and macOS."
        print_info "📋 You can view the release at: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:\/]\([^.]*\).*/\1/')/releases"
    fi
}

# Run main function
main "$@"