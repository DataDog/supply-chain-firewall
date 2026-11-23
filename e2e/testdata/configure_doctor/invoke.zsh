set -eu
source "$HOME/.zshrc"
alias npm
npm install "$SCFW_E2E_PACKAGE" --ignore-scripts --no-audit --no-fund
