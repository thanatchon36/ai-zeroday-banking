#!/usr/bin/env bash
# Reproduce every number, table and figure, then compile the paper.
set -euo pipefail
cd "$(dirname "$0")"
[ -f data/raw/cves.zip ] && [ -f data/raw/kev.json ] || bash src/s00_fetch_data.sh
python3 src/s01_extract_cve.py
python3 src/s02_ai_credits.py
python3 src/s03_kev_panel.py
python3 src/s04_analysis.py > /dev/null
python3 src/s05_cases.py
python3 src/s06_thai_framework.py
python3 src/s07_simulation.py
python3 src/s08_figures.py
mkdir -p paper/figures && for f in outputs/figures/*.pdf; do mv "$f" paper/figures/; done
python3 src/s09_latex_tables.py
cd paper && latexmk -pdf -interaction=nonstopmode main.tex && cp main.pdf ../paper.pdf
echo "done: paper.pdf"
