#!/usr/bin/env bash
# Re-render the PNG copies of the SVG graphics so the two never drift apart.
# (An older PNG set in this repo kept claims the SVGs had already corrected.)
# Requires rsvg-convert:  sudo apt install librsvg2-bin
set -euo pipefail
cd "$(dirname "$0")/.."

render() {
  rsvg-convert -w "$2" "$1" -o "${1%.svg}.png"
  echo "rendered ${1%.svg}.png"
}

render assets/project-cover.svg                   1920
render assets/architecture/lab-architecture.svg   2560
render assets/diagrams/detection-pipeline.svg     2200
render assets/diagrams/investigation-workflow.svg 2200
