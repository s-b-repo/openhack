#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log(){ echo -e "${GREEN}[+]${NC} $*" ; }
warn(){ echo -e "${YELLOW}[!]${NC} $*" ; }
err(){ echo -e "${RED}[-]${NC} $*" ; exit 1 ; }
info(){ echo -e "${CYAN}[*]${NC} $*" ; }

# --dry-run previews every mutating step instead of executing it.
DRY_RUN="${DRY_RUN:-0}"
for a in "$@"; do [ "$a" = "--dry-run" ] && DRY_RUN=1; done
run(){ if [ "$DRY_RUN" = "1" ]; then echo -e "${CYAN}[dry-run]${NC} $*"; else eval "$@"; fi; }

OPENHACK_DIR="${OPENHACK_DIR:-$HOME/openhack}"
OPENHACK_MCP_DIR="${OPENHACK_MCP_DIR:-$HOME/.local/share/openhack/mcp-servers}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/openhack"
REPO_URL="https://github.com/s-b-repo/openhack.git"

echo -e "${RED}"
cat << "EOF"
  ___                   __  __           __
 / _ \ ___  ___ ________/ / / / ___ _____/ /__
/ // / _ \/ _\`/ __/ _  / _  / / _\`/ __/  '_/
\___/ .__/\_,_/\__/\_,_/_/ /_/  \_,_/\__/_/\_\\
   /_/
EOF
echo -e "${NC}"
info "OpenHack v0.2.0 — Installer"

OS="$(uname -s)"
case "$OS" in Linux|Darwin) info "Detected: $OS" ;; *) err "Unsupported: $OS" ;; esac

if command -v bun &>/dev/null; then log "bun $(bun --version)" ; else
    info "Installing bun..." ; curl -fsSL https://bun.sh/install | bash
    export BUN_INSTALL="$HOME/.bun" ; export PATH="$BUN_INSTALL/bin:$PATH" ; fi

if [ "$OS" = "Linux" ]; then
    MISSING=""
    command -v gcc &>/dev/null || MISSING="$MISSING build-essential"
    command -v pkg-config &>/dev/null || MISSING="$MISSING pkg-config"
    dpkg -s libssl-dev &>/dev/null 2>&1 || MISSING="$MISSING libssl-dev"
    [ -n "$MISSING" ] && { info "Installing: $MISSING" ; sudo apt-get update -qq && sudo apt-get install -y -qq $MISSING ; }
fi

if [ -d "$OPENHACK_DIR/.git" ]; then
    info "Updating OpenHack..." ; run "git -C '$OPENHACK_DIR' pull --ff-only || true"
else
    info "Cloning OpenHack..."
    [ ! -d "$OPENHACK_DIR" ] && run "git clone --depth 1 '$REPO_URL' '$OPENHACK_DIR'"
fi

info "Installing dependencies..."
cd "$OPENHACK_DIR"
run "bun install --frozen-lockfile 2>/dev/null || bun install"

mkdir -p "$CONFIG_DIR" "$HOME/.local/share/openhack"

if [ ! -f "$CONFIG_DIR/openhack.json" ]; then
    if [ -f "$OPENHACK_DIR/.openhack/openhack.jsonc" ]; then
        cp "$OPENHACK_DIR/.openhack/openhack.jsonc" "$CONFIG_DIR/openhack.json"
        log "Config created at $CONFIG_DIR/openhack.json"
    fi
fi

# Create runtime dirs always
mkdir -p "$OPENHACK_DIR/.openhack/"{agents,plans,reports,findings,secrets,recovery,logs,resources,roe,workflows,automode-results}
log "Runtime directories created"

# Create single binary wrapper
sudo tee /usr/local/bin/openhack > /dev/null << 'BINEOF'
#!/bin/bash
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
exec bun run "$HOME/openhack/packages/openhack-cli/src/index.ts" "$@"
BINEOF
sudo chmod +x /usr/local/bin/openhack 2>/dev/null || true
log "Installed /usr/local/bin/openhack"

SHELL_CONFIG=""
case "$SHELL" in
    */zsh)  SHELL_CONFIG="$HOME/.zshrc" ;;
    */bash) SHELL_CONFIG="$HOME/.bashrc" ;;
    */fish) SHELL_CONFIG="$HOME/.config/fish/config.fish" ;;
esac

if [ -n "$SHELL_CONFIG" ] && [ -f "$SHELL_CONFIG" ]; then
    if ! grep -q "oh=" "$SHELL_CONFIG" 2>/dev/null; then
        echo 'alias oh="cd $HOME/openhack && bun run packages/openhack-cli/src/index.ts"' >> "$SHELL_CONFIG"
        log "Added 'oh' alias to $SHELL_CONFIG"
    fi
    if ! grep -q "RUSTSPLOIT_PATH" "$SHELL_CONFIG" 2>/dev/null; then
        echo "export RUSTSPLOIT_PATH=\"$OPENHACK_MCP_DIR/rustsploit/target/release/rustsploit\"" >> "$SHELL_CONFIG"
        echo "export ARCTICFOX_PATH=\"$OPENHACK_MCP_DIR/arcticfox-c3/target/release/arcticfox-mcp\"" >> "$SHELL_CONFIG"
    fi
fi

echo ""
info "Scope Configuration"
echo "  Define your engagement scope in $CONFIG_DIR/openhack.json"
echo "  Add targets, exclusions, and tool restrictions under 'scope' section."
echo "  The scope enforcer validates every tool call against this config."
echo ""

echo ""
info "MCP Server Setup (optional)"
echo "  [1] HexStrike AI   (10.1k stars) — 150+ cybersecurity tools"
echo "  [2] pentest-ai      (1.2k stars) — 200+ tools, verified exploits"
echo "  [3] rustsploit        (56 stars) — Rust exploitation framework + MCP"
echo "  [4] arcticfox-c3                  — C2 framework + MCP"
echo "  [5] SysReptor        (2.5k stars) — Pentest reporting platform"
echo "  [A] Install ALL"
echo "  [N] Skip"
FULL=0
for a in "$@"; do [ "$a" = "--full" ] && FULL=1; done
[ "${OPENHACK_FULL:-0}" = "1" ] && FULL=1

if [ "$FULL" = "1" ]; then
  CHOICE="A"
  info "FULL deploy: Kali tools + camoufox (stealth browser) + OnlyOffice (reports) + all pentest MCPs"
elif [ -t 0 ] && [ "$DRY_RUN" != "1" ]; then
  read -p "Select [1-5/A/N]: " CHOICE
else
  CHOICE="N"
  [ "$DRY_RUN" = "1" ] || info "Non-interactive mode: skipping MCP setup (use --full for everything)"
fi

install_hexstrike(){
    info "Installing HexStrike AI..."
    mkdir -p "$OPENHACK_MCP_DIR"
    if [ ! -d "$OPENHACK_MCP_DIR/hexstrike-ai" ]; then
        git clone --depth 1 https://github.com/0x4m4/hexstrike-ai.git "$OPENHACK_MCP_DIR/hexstrike-ai"
    fi
    cd "$OPENHACK_MCP_DIR/hexstrike-ai"
    python3 -m venv hexstrike-env 2>/dev/null || true
    source hexstrike-env/bin/activate
    pip install -r requirements.txt -q
    deactivate
    echo "export HEXSTRIKE_PATH=\"$OPENHACK_MCP_DIR/hexstrike-ai\"" >> "$SHELL_CONFIG" 2>/dev/null || true
    log "HexStrike AI → $OPENHACK_MCP_DIR/hexstrike-ai"
}

install_pentestai(){
    info "Installing pentest-ai..." ; pip install ptai -q 2>/dev/null || pip install ptai
    log "pentest-ai installed"
}

install_rustsploit(){
    info "Installing rustsploit..."
    if ! command -v cargo &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    mkdir -p "$OPENHACK_MCP_DIR"
    if [ ! -d "$OPENHACK_MCP_DIR/rustsploit" ]; then
        git clone --depth 1 https://github.com/s-b-repo/rustsploit.git "$OPENHACK_MCP_DIR/rustsploit"
    fi
    cd "$OPENHACK_MCP_DIR/rustsploit"
    cargo build --release 2>&1 | tail -20
    log "rustsploit → $OPENHACK_MCP_DIR/rustsploit"
}

install_arcticfox(){
    info "Installing arcticfox-c3..."
    if ! command -v cargo &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    mkdir -p "$OPENHACK_MCP_DIR"
    if [ ! -d "$OPENHACK_MCP_DIR/arcticfox-c3" ]; then
        git clone --depth 1 https://github.com/s-b-repo/arcticfox-c3.git "$OPENHACK_MCP_DIR/arcticfox-c3"
    fi
    cd "$OPENHACK_MCP_DIR/arcticfox-c3"
    cargo build --release --bin arcticfox-mcp 2>&1 | tail -20
    log "arcticfox-c3 → $OPENHACK_MCP_DIR/arcticfox-c3"
}

install_sysreptor(){
    info "SysReptor requires Docker. See: https://docs.sysreptor.com/setup/installation/"
    info "After installing, set SYSREPTOR_URL and SYSREPTOR_API_TOKEN."
    info "Quick start: docker run -d -p 8000:8000 syslifters/sysreptor:latest"
}

install_kali_tools(){
    [ "$OS" = "Linux" ] || { warn "Kali tools step is Linux-only"; return 0; }
    command -v pipx &>/dev/null || run "sudo apt-get install -y -qq pipx"
    info "Installing default pentest tools + Xvfb (for the stealth browser)"
    run "sudo apt-get update -qq"
    run "sudo apt-get install -y -qq xvfb nmap nuclei sqlmap gobuster ffuf nikto whatweb wpscan amass subfinder dnsenum hydra john hashcat masscan dirsearch dalfox seclists 2>/dev/null || true"
    log "Kali tools + Xvfb installed (missing ones can be added via apt)"
}

install_camoufox(){
    command -v pipx &>/dev/null || run "sudo apt-get install -y -qq pipx"
    info "Installing Camoufox stealth browser (Cloudflare-managed-challenge bypass)"
    run "pipx install camoufox"
    run "camoufox fetch"
    # playwright MUST be 1.49.1 — newer breaks Camoufox's Juggler protocol
    run "pipx inject camoufox 'playwright==1.49.1' 'mcp>=1.2'"
    log "Camoufox → server: packages/openhack/mcp/camoufox_mcp.py  (enable: openhack config set mcp.camoufox.enabled true)"
}

install_onlyoffice(){
    info "Installing OnlyOffice MCP (docx/xlsx/pptx report generation — replaces SysReptor)"
    if command -v onlyoffice-mcp &>/dev/null; then
        log "OnlyOffice MCP already installed ($(command -v onlyoffice-mcp))"
    elif [ -d "$HOME/onlyoffice-mcp" ]; then
        run "python3 -m venv '$HOME/onlyoffice-mcp/.venv'"
        run "'$HOME/onlyoffice-mcp/.venv/bin/pip' install -q -e '$HOME/onlyoffice-mcp'"
        log "OnlyOffice MCP → $HOME/onlyoffice-mcp/.venv/bin/onlyoffice-mcp"
    else
        run "pipx install onlyoffice-mcp" || warn "OnlyOffice MCP not found on PyPI — clone it to ~/onlyoffice-mcp then re-run"
    fi
    log "OnlyOffice → enable: openhack config set mcp.onlyoffice.enabled true"
}

install_lattice(){
    # The structural code-audit engine ships vendored in the repo — bootstrap its
    # self-contained venv so /codeaudit works with no global install. Idempotent.
    local lattice_dir
    lattice_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vendor/lattice"
    if [ ! -d "$lattice_dir" ]; then
        warn "vendor/lattice missing from this checkout — skipping (codeaudit falls back to PATH 'lattice')"
        return 0
    fi
    info "Bootstrapping Lattice code-audit engine (vendored, no global install)"
    run "bash '$lattice_dir/bootstrap.sh'" || warn "Lattice bootstrap failed — /codeaudit will fall back to PATH"
    log "Lattice → $lattice_dir/.venv/bin/lattice (used automatically by lattice-codeaudit)"
}

install_dcr(){
    # The Dynamic Context Runtime ships vendored (vendor/subnext) — build its
    # self-contained binary so the dcr bridge works with no global install.
    # Idempotent; resolution prefers the vendored binary over PATH automatically.
    local subnext_dir
    subnext_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vendor/subnext"
    if [ ! -d "$subnext_dir" ]; then
        warn "vendor/subnext missing from this checkout — skipping (dcr falls back to PATH 'dcr')"
        return 0
    fi
    info "Bootstrapping Dynamic Context Runtime (vendored, no global install)"
    run "bash '$subnext_dir/bootstrap.sh'" || warn "dcr bootstrap failed — sessions degrade to full history unless 'dcr' is on PATH"
    log "dcr → $subnext_dir/bin/dcr (resolved automatically by the session runner)"
}

install_staged_vendors(){
    # Opt-in sweep for the staged sidecars (python venvs / rust / go builds).
    # Heavy and network-bound — enable with OPENHACK_BOOTSTRAP_ALL=1.
    local root
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for name in mini-swe-agent gpt-researcher deepagents langgraph graphbit temporal; do
        local dir="$root/vendor/$name"
        [ -d "$dir" ] || continue
        if bash "$dir/bootstrap.sh" --check >/dev/null 2>&1; then
            log "vendor/$name already bootstrapped"
            continue
        fi
        info "Bootstrapping vendor/$name (staged sidecar)"
        run "bash '$dir/bootstrap.sh'" || warn "vendor/$name bootstrap failed — it stays a staged component (see vendor/README.md)"
    done
}

case "$CHOICE" in
    1) install_hexstrike ;;
    2) install_pentestai ;;
    3) install_rustsploit ;;
    4) install_arcticfox ;;
    5) install_sysreptor ;;
    A|a) install_hexstrike ; install_pentestai ; install_rustsploit ; install_arcticfox ; install_sysreptor ;;
    *) info "Skipping MCP setup" ;;
esac

if [ "$FULL" = "1" ]; then
    install_kali_tools
    install_camoufox
    install_onlyoffice
    install_lattice
    install_dcr
    if [ "${OPENHACK_BOOTSTRAP_ALL:-0}" = "1" ]; then
        install_staged_vendors
    else
        info "Staged vendor sidecars not built (set OPENHACK_BOOTSTRAP_ALL=1 to bootstrap them)"
    fi
    echo ""
    log "Full deploy complete. Enable the local MCPs you want:"
    echo "  openhack config set mcp.camoufox.enabled true      # stealth browser (WAF/Cloudflare)"
    echo "  openhack config set mcp.onlyoffice.enabled true    # docx/xlsx/pptx reports"
    echo "  openhack config set mcp.filesystem.enabled true    # + git/fetch/memory as needed"
fi

# The code-audit engine is core tooling — bootstrap it on every path unless dry-running.
install_lattice


echo ""
log "OpenHack v0.2.0 installation complete!"
echo ""
info "Quick Start:"
echo "  cd $OPENHACK_DIR && bun run packages/openhack-cli/src/index.ts"
info "Or restart shell and run: oh"
echo ""
info "Next Steps:"
echo "  1. Deploy MCP Docker containers:  bash openhack-setup.sh"
echo "  2. OR configure manually in $CONFIG_DIR/openhack.json"
echo "  3. Configure LLM provider: /connect"
echo ""
echo "One-line FULL setup + deploy (bun, build, Kali tools, camoufox, OnlyOffice, all MCPs):"
echo "  curl -fsSL https://raw.githubusercontent.com/s-b-repo/openhack/main/install.sh | OPENHACK_FULL=1 bash"
echo "  (preview steps first with:  bash install.sh --dry-run --full )"
echo ""
info "Start with: oh"
echo ""
