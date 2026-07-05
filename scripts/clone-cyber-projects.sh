#!/usr/bin/env bash
# Clone all numbered cyber projects into cyber-projects/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/cyber-projects"
mkdir -p "$DEST"
cd "$DEST"

clone_if_missing() {
  local dir="$1" url="$2"
  if [ ! -d "$dir" ]; then
    git clone --depth 1 "$url" "$dir"
  fi
}

clone_if_missing "04-jailbreak-threat-landscape" "https://github.com/kevinb28-21/cybersec-04-jailbreak-threat-landscape.git"
clone_if_missing "05-ai-agent-security-testing-lab" "https://github.com/kevinb28-21/cybersec-05-ai-agent-security-testing-lab.git"
clone_if_missing "06-rag-poisoning-attack-simulation" "https://github.com/kevinb28-21/cybersec-06-rag-poisoning-attack-simulation.git"
clone_if_missing "07-steganographic-prompt-injection" "https://github.com/kevinb28-21/cybersec-07-steganographic-prompt-injection.git"
clone_if_missing "08-llm-container-escape-testing" "https://github.com/kevinb28-21/cybersec-08-llm-container-escape-testing.git"
clone_if_missing "09-adversarial-attack-on-ai-ids" "https://github.com/kevinb28-21/cybersec-09-adversarial-attack-on-ai-ids.git"
clone_if_missing "10-ai-red-team-full-exercise" "https://github.com/kevinb28-21/cybersec-10-ai-red-team-full-exercise.git"

echo "All cyber projects cloned to $DEST"
