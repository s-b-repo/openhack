#!/usr/bin/env bash
# Re-arm the ground-truth regression gate (tests/test_corpus_regression.py) by fetching the
# fresh vulnerable corpora into $FOOTINGS_CORPUS (default ~/.footings-corpus). The smartbugs
# corpus is referenced separately via $FOOTINGS_SMARTBUGS. Run once after a clean checkout /
# after the durable copy is lost:  bash tests/fetch_corpora.sh
set -euo pipefail
DEST="${FOOTINGS_CORPUS:-$HOME/.footings-corpus}"
mkdir -p "$DEST"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "fetching corpora into $DEST ..."
git clone --depth 1 -q https://github.com/crytic/not-so-smart-contracts.git "$tmp/nssc"
cp -R "$tmp/nssc" "$DEST/nssc"

git clone --depth 1 -q https://github.com/DependableSystemsLab/SolidiFI-benchmark.git "$tmp/sf"
mkdir -p "$DEST/solidifi"; cp -R "$tmp/sf/buggy_contracts" "$DEST/solidifi/buggy_contracts"

git clone --depth 1 -q https://github.com/OpenZeppelin/openzeppelin-contracts.git "$tmp/oz"
mkdir -p "$DEST/oz"; cp -R "$tmp/oz/contracts" "$DEST/oz/contracts"

echo "done. nssc=$(find "$DEST/nssc" -name '*.sol'|wc -l) solidifi=$(find "$DEST/solidifi" -name '*.sol'|wc -l) oz=$(find "$DEST/oz" -name '*.sol'|wc -l)"
echo "run the gate:  FOOTINGS_CORPUS_GATE=1 pytest tests/test_corpus_regression.py -v"
