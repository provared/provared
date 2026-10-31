#!/bin/sh
# Fails if the saved output of a "node --test" run holds a warning from
# Node.js other than its notice that ML-DSA or SLH-DSA is experimental.
# Usage: sh tools/lint/node-warnings.sh <file with the run's output>
#
# Node.js prints each warning on a line of its own that begins "(node:" and
# the process number. The one expected warning is Node.js's notice that the
# post-quantum signing methods the library uses are experimental.
set -eu
output=$1
others=$(grep -E '^\(node:[0-9]+\) ' "$output" | grep -v -E 'ExperimentalWarning: The (ML-DSA|SLH-DSA)[-A-Za-z0-9]* ' || true)
if [ -n "$others" ]; then
  echo "$others"
  echo "::error::The tests printed a warning other than Node.js's notice that ML-DSA or SLH-DSA is experimental (above)."
  exit 1
fi
echo "No warning but Node.js's notice that ML-DSA or SLH-DSA is experimental."
