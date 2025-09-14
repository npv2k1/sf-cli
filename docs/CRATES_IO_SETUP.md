# Crates.io Publishing Setup

This document explains how to set up automatic publishing to Crates.io for the sf-cli package.

## Required Setup

### 1. Create a Crates.io Account and API Token

1. Visit [crates.io](https://crates.io) and create an account if you don't have one
2. Go to your [Account Settings](https://crates.io/settings/tokens)
3. Create a new API token:
   - Name: `sf-cli-github-actions` (or similar descriptive name)
   - Scopes: Select `publish-new` or `publish-update` depending on your needs
4. Copy the generated token (it starts with `crates-io_`)

### 2. Add the Token to GitHub Secrets

1. Go to your GitHub repository settings
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `CRATES_IO_TOKEN`
5. Value: Paste your Crates.io API token
6. Click **Add secret**

## How It Works

The release workflow (`/.github/workflows/release.yml`) now includes a `publish-to-crates` job that:

- Only runs when a Git tag is pushed (e.g., `v1.0.0`)
- Builds the package and publishes it to Crates.io using the API token
- Runs in parallel with the GitHub release creation

## Publishing a New Version

1. Update the version in `Cargo.toml`
2. Commit the change: `git commit -am "Bump version to x.y.z"`
3. Create and push a tag: `git tag vx.y.z && git push origin vx.y.z`
4. The GitHub Action will automatically:
   - Build binaries for multiple platforms
   - Create a GitHub release
   - Publish the package to Crates.io

## Troubleshooting

- **Token Issues**: Make sure the `CRATES_IO_TOKEN` secret is set correctly
- **Publishing Fails**: Check that the version number in `Cargo.toml` hasn't been published before
- **Build Failures**: The package must build successfully before it can be published

## Package Metadata

The package is configured with:
- Keywords: `encryption`, `security`, `cli`, `tui`, `file`
- Categories: `cryptography`, `command-line-utilities`
- License: `MIT OR Apache-2.0`
- Homepage and repository links to this GitHub repo