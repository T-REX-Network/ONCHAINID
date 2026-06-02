#!/bin/bash

FAIL=0

# Thresholds — set below 100% because --ir-minimum (required for P256.sol stack-too-deep
# workaround) produces inaccurate source mappings in Foundry. Some lines/statements/functions
# that are provably executed appear as "uncovered" due to Yul IR codegen source map mismatches.
# This is a known Foundry limitation confirmed by the OpenZeppelin team.
LINE_THRESHOLD=94
STMT_THRESHOLD=95
FUNC_THRESHOLD=98

echo "Generating coverage report..."
COVERAGE_OUTPUT=$(forge coverage --no-match-coverage "(test|script|dependencies|FormatResolver|WebAuthnValidator)" --ir-minimum --report summary)

# Display the coverage report
echo "=== Coverage Report ==="
echo "$COVERAGE_OUTPUT"
echo "======================="

TOTAL_LINE=$(echo "$COVERAGE_OUTPUT" | grep "| Total.*|")

if [ -z "$TOTAL_LINE" ]; then
    echo "❌ Could not find Total coverage line"
    exit 1
fi

LINE_COV=$(echo "$TOTAL_LINE" | awk -F'|' '{print $3}' | grep -o '[0-9]*\.[0-9]*%' | sed 's/%//')
STMT_COV=$(echo "$TOTAL_LINE" | awk -F'|' '{print $4}' | grep -o '[0-9]*\.[0-9]*%' | sed 's/%//')
BRANCH_COV=$(echo "$TOTAL_LINE" | awk -F'|' '{print $5}' | grep -o '[0-9]*\.[0-9]*%' | sed 's/%//')
FUNC_COV=$(echo "$TOTAL_LINE" | awk -F'|' '{print $6}' | grep -o '[0-9]*\.[0-9]*%' | sed 's/%//')

if [ "$(echo "$LINE_COV < $LINE_THRESHOLD" | bc -l)" = "1" ]; then
    echo "❌ Line coverage ($LINE_COV%) is below ${LINE_THRESHOLD}%"
    FAIL=1
fi

if [ "$(echo "$STMT_COV < $STMT_THRESHOLD" | bc -l)" = "1" ]; then
    echo "❌ Statement coverage ($STMT_COV%) is below ${STMT_THRESHOLD}%"
    FAIL=1
fi

# Branch coverage not enforced — --ir-minimum breaks branch source mappings (Foundry limitation)
echo "ℹ️  Branch coverage ($BRANCH_COV%) — not enforced (--ir-minimum source mapping limitation)"

if [ "$(echo "$FUNC_COV < $FUNC_THRESHOLD" | bc -l)" = "1" ]; then
    echo "❌ Function coverage ($FUNC_COV%) is below ${FUNC_THRESHOLD}%"
    FAIL=1
fi

if [ $FAIL = 1 ]; then
    echo ""
    echo "Coverage check failed!"
    exit 1
else
    echo "✅ Coverage requirements met! (Line: ${LINE_COV}%, Stmt: ${STMT_COV}%, Func: ${FUNC_COV}%)"
fi
