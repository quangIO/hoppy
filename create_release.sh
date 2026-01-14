#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYPROJECT_TOML="pyproject.toml"
REMOTE="origin"
MAIN_BRANCH="main"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get current version from pyproject.toml
get_current_version() {
    grep "^version = " "$PYPROJECT_TOML" | sed 's/version = "\(.*\)"/\1/' | tr -d '"'
}

# Function to increment version
increment_version() {
    local version=$1
    local bump_type=$2

    # Split version into components
    local major minor patch
    IFS='.' read -r major minor patch <<< "$version"

    case $bump_type in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            print_error "Invalid bump type. Use: major, minor, or patch"
            exit 1
            ;;
    esac

    echo "${major}.${minor}.${patch}"
}

# Function to update version in pyproject.toml
update_version() {
    local new_version=$1
    local os=$(uname)

    if [[ "$os" == "Darwin" ]]; then
        # macOS
        sed -i '' "s/^version = .*/version = \"$new_version\"/" "$PYPROJECT_TOML"
    else
        # Linux
        sed -i "s/^version = .*/version = \"$new_version\"/" "$PYPROJECT_TOML"
    fi
}

# Function to check if git is clean
check_git_clean() {
    if [[ -n $(git status --porcelain) ]]; then
        print_error "Working directory is not clean. Please commit or stash changes first."
        exit 1
    fi
}

# Function to check if we're on main branch
check_branch() {
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$current_branch" != "$MAIN_BRANCH" ]]; then
        print_warning "You are not on '$MAIN_BRANCH' branch (currently on '$current_branch')"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Aborted"
            exit 0
        fi
    fi
}

# Main script
main() {
    print_info "Starting release process..."

    # Check arguments
    if [[ $# -eq 0 ]]; then
        print_error "Usage: $0 <major|minor|patch> [--dry-run]"
        exit 1
    fi

    BUMP_TYPE=$1
    DRY_RUN=false

    if [[ "${2:-}" == "--dry-run" ]]; then
        DRY_RUN=true
        print_info "DRY RUN MODE - No changes will be made"
    fi

    # Validate bump type
    if [[ ! "$BUMP_TYPE" =~ ^(major|minor|patch)$ ]]; then
        print_error "Invalid bump type: $BUMP_TYPE"
        print_info "Use: major, minor, or patch"
        exit 1
    fi

    # Check prerequisites
    check_git_clean
    check_branch

    # Get current version
    current_version=$(get_current_version)
    print_info "Current version: $current_version"

    # Calculate new version
    new_version=$(increment_version "$current_version" "$BUMP_TYPE")
    print_info "New version: $new_version ($BUMP_TYPE bump)"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "Dry run complete. No changes made."
        exit 0
    fi

    # Confirm release
    echo
    read -p "Release version $new_version? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted"
        exit 0
    fi

    # Update version in pyproject.toml
    print_info "Updating version in pyproject.toml..."
    update_version "$new_version"

    # Run tests
    print_info "Running tests..."
    if ! uv run pytest -v; then
        print_error "Tests failed. Aborting release."
        git restore "$PYPROJECT_TOML"
        exit 1
    fi
    print_success "Tests passed"

    # Run linting
    print_info "Running linting..."
    if ! uv run ruff check .; then
        print_error "Linting failed. Aborting release."
        git restore "$PYPROJECT_TOML"
        exit 1
    fi
    print_success "Linting passed"

    # Build package
    print_info "Building package..."
    if ! uv build; then
        print_error "Build failed. Aborting release."
        git restore "$PYPROJECT_TOML"
        exit 1
    fi
    print_success "Build successful"

    # Commit changes
    print_info "Committing version bump..."
    git add "$PYPROJECT_TOML"
    git commit -m "chore: bump version to $new_version"

    # Create tag
    print_info "Creating git tag v$new_version..."
    git tag -a "v$new_version" -m "Release version $new_version"

    # Push to remote
    print_info "Pushing to $REMOTE..."
    git push "$REMOTE" "$MAIN_BRANCH"
    git push "$REMOTE" "v$new_version"

    print_success "Release v$new_version created successfully!"
    print_info "Next steps:"
    print_info "  1. Go to https://github.com/$(git remote get-url $REMOTE | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/releases"
    print_info "  2. Create a new release from tag v$new_version"
    print_info "  3. The CI/CD pipeline will automatically publish to PyPI"
}

main "$@"
