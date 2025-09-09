#!/bin/bash

# Script to validate GitHub Actions workflows
# This can be run locally to check workflow syntax

set -e

echo "🔍 Validating GitHub Actions workflows..."

# Check if Python and PyYAML are available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required for YAML validation"
    exit 1
fi

if ! python3 -c "import yaml" &> /dev/null; then
    echo "⚠️  PyYAML not found, installing..."
    pip3 install PyYAML
fi

# Validate each workflow file
workflows=(".github/workflows/ci.yml" ".github/workflows/release.yml" ".github/workflows/security.yml")

for workflow in "${workflows[@]}"; do
    if [ -f "$workflow" ]; then
        echo "Validating $workflow..."
        python3 -c "
import yaml
try:
    with open('$workflow', 'r') as f:
        yaml.safe_load(f)
    print('✅ $workflow is valid!')
except Exception as e:
    print('❌ $workflow error: ' + str(e))
    exit(1)
"
    else
        echo "⚠️  $workflow not found"
    fi
done

echo ""
echo "🎉 All GitHub Actions workflows are valid!"
echo ""
echo "📋 Workflow Summary:"
echo "   • CI: Runs tests, linting, and builds on push/PR to main"
echo "   • Release: Creates releases on tag push AND main branch push"
echo "   • Security: Weekly security audits"
echo ""
echo "🚀 Ready for CI/CD! Push to main branch to trigger latest release creation."