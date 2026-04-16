#!/bin/bash
set -e

echo "============================================"
echo "  db-hygiene-scanner Demo Runner"
echo "  Version: 0.1.0-alpha"
echo "============================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "  Python $PYTHON_VERSION"

# Determine script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
MOCK_REPO="$PROJECT_DIR/demo/mock_bank_repo/src"

if [ ! -d "$MOCK_REPO" ]; then
    echo "ERROR: Mock bank repo not found at $MOCK_REPO"
    exit 1
fi
echo "  Mock repo found at $MOCK_REPO"

# Install tool if needed
echo ""
echo "Ensuring db-hygiene-scanner is installed..."
cd "$PROJECT_DIR"
pip install -e . > /dev/null 2>&1
echo "  Installation verified"

# Step 1: Run scan
echo ""
echo "============================================"
echo "  Step 1: Scanning mock banking repository"
echo "============================================"
echo ""

python3 -m db_hygiene_scanner.cli scan "$MOCK_REPO" --output-file /tmp/demo-scan-results.json

echo ""
echo "  Scan results saved to /tmp/demo-scan-results.json"

# Step 2: Show statistics
echo ""
echo "============================================"
echo "  Step 2: Scan Statistics"
echo "============================================"
echo ""

python3 -c "
import json
d = json.load(open('/tmp/demo-scan-results.json'))
print(f'  Files scanned: {d[\"stats\"][\"total_files_scanned\"]}')
print(f'  Total violations: {d[\"stats\"][\"total_violations\"]}')
print(f'  Scan duration: {d[\"stats\"][\"scan_duration_seconds\"]:.2f}s')
print()
print('  Violations by type:')
for k, v in d['stats'].get('violations_by_type', {}).items():
    print(f'    {k}: {v}')
print()
print('  Violations by platform:')
for k, v in d['stats'].get('violations_by_platform', {}).items():
    print(f'    {k}: {v}')
"

# Step 3: Optional AI fixes
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "============================================"
    echo "  Step 3: AI Fix Generation (API key found)"
    echo "============================================"
    echo ""
    echo "  Skipping AI fix generation in demo mode."
    echo "  To generate fixes, run:"
    echo "    db-hygiene-scanner fix $MOCK_REPO --output-file fixes.json"
else
    echo ""
    echo "  Note: Set ANTHROPIC_API_KEY to enable AI fix generation"
fi

echo ""
echo "============================================"
echo "  Demo Complete!"
echo "============================================"
echo ""
echo "  Next steps:"
echo "    1. Review scan results: cat /tmp/demo-scan-results.json | python3 -m json.tool"
echo "    2. Generate fixes: db-hygiene-scanner fix $MOCK_REPO"
echo "    3. Create PR: See CI/CD pipeline documentation"
echo ""
