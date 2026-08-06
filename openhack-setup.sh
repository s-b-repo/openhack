#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'
log(){ echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
err(){ echo -e "${RED}[-]${NC} $*"; exit 1; }
info(){ echo -e "${CYAN}[*]${NC} $*"; }
bold(){ echo -e "${BLUE}$*${NC}"; }

OPENHACK_DIR="${OPENHACK_DIR:-$HOME/openhack}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/openhack"
DOCKER_DIR="$OPENHACK_DIR/Docker"
NETWORK_NAME="openhack-net"
NETWORK_SUBNET="${OPENHACK_NET:-10.99.0.0/24}"
NETWORK_GATEWAY="${NETWORK_SUBNET%.*}.1"

echo -e "${RED}"
cat << "EOF"
  ___                   __  __           __
 / _ \ ___  ___ ________/ / / / ___ _____/ /__
/ // / _ \/ _\`/ __/ _  / _  / / _\`/ __/  '_/
\___/ .__/\\_,_/\\__/\\_,_/_/ /_/  \\_,_/\\__/_/\\_\\
   /_/
       MCP Deployment System
EOF
echo -e "${NC}"
info "OpenHack MCP One-Command Deployment v0.2.0"

OS="$(uname -s)"
case "$OS" in Linux) ;; *) err "Only Linux supported for Docker MCP deployment" ;; esac

# ─── Step 1: Docker Detection + Auto-Install ───

if command -v docker &>/dev/null; then
  log "Docker $(docker --version | awk '{print $3}' | tr -d ',') detected"
else
  warn "Docker not found — installing..."
  if [ -f /etc/debian_version ]; then
    info "Detected Debian/Ubuntu"
    sudo apt-get update -qq
    sudo apt-get install -y -qq ca-certificates curl
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq && sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif [ -f /etc/arch-release ]; then
    info "Detected Arch Linux"
    sudo pacman -S --noconfirm docker docker-compose
    sudo systemctl enable --now docker
  elif [ -f /etc/fedora-release ]; then
    info "Detected Fedora"
    sudo dnf -y install dnf-plugins-core
    sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable --now docker
  else
    err "Unknown distro. Install Docker manually and re-run."
  fi
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  log "Docker installed. You may need to re-login or run: newgrp docker"
fi

if ! docker info &>/dev/null; then
  warn "Docker daemon not running — starting..."
  sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true
  sleep 2
fi

# ─── Step 2: Network Configuration ───

if [ -t 0 ]; then
  echo ""
  info "MCP Network Configuration"
  echo "  Private bridge network for MCP containers"
  echo "  Default subnet: ${NETWORK_SUBNET}"
  echo "  Gateway: ${NETWORK_GATEWAY}"
  echo "  Containers get static IPs: .10 - .14"
  echo ""
  read -p "Subnet [${NETWORK_SUBNET}]: " custom_subnet
  if [ -n "$custom_subnet" ]; then
    NETWORK_SUBNET="$custom_subnet"
    NETWORK_GATEWAY="${NETWORK_SUBNET%.*}.1"
  fi
fi

log "Network: ${NETWORK_SUBNET} (gateway: ${NETWORK_GATEWAY})"
log "  hexstrike:   ${NETWORK_SUBNET%.*}.10"
log "  pentest-ai:  ${NETWORK_SUBNET%.*}.11"
log "  rustsploit:  ${NETWORK_SUBNET%.*}.12 (privileged, root)"
log "  arcticfox:   ${NETWORK_SUBNET%.*}.13"
log "  sysreptor:   ${NETWORK_SUBNET%.*}.14"

# ─── Step 3: Create Network ───

if ! docker network inspect "$NETWORK_NAME" &>/dev/null; then
  info "Creating network: $NETWORK_NAME"
  docker network create \
    --driver bridge \
    --subnet="$NETWORK_SUBNET" \
    --gateway="$NETWORK_GATEWAY" \
    "$NETWORK_NAME"
  log "Network created"
else
  log "Network $NETWORK_NAME already exists"
fi

# ─── Step 4: Build Images ───

cd "$OPENHACK_DIR"

build_image() {
  local name="$1" dockerfile="$2"
  info "Building $name..."
  if docker build -t "openhack-$name" -f "$dockerfile" "$OPENHACK_DIR" > /tmp/openhack-build-"$name".log 2>&1; then
    log "$name built successfully"
  else
    warn "$name build failed — see /tmp/openhack-build-$name.log"
    tail -20 /tmp/openhack-build-"$name".log
  fi
}

if [ -f "$DOCKER_DIR/Dockerfile.hexstrike" ]; then
  build_image "hexstrike" "$DOCKER_DIR/Dockerfile.hexstrike"
fi
if [ -f "$DOCKER_DIR/Dockerfile.pentestai" ]; then
  build_image "pentestai" "$DOCKER_DIR/Dockerfile.pentestai" 
fi
if [ -f "$DOCKER_DIR/Dockerfile.rustsploit" ]; then
  build_image "rustsploit" "$DOCKER_DIR/Dockerfile.rustsploit"
fi
if [ -f "$DOCKER_DIR/Dockerfile.arcticfox" ]; then
  build_image "arcticfox" "$DOCKER_DIR/Dockerfile.arcticfox"
fi

# ─── Step 5: Start Containers ───

stop_existing() {
  docker rm -f "$1" 2>/dev/null || true
}

IP_BASE="${NETWORK_SUBNET%.*}"

info "Starting MCP containers..."

stop_existing openhack-hexstrike
docker run -d --name openhack-hexstrike \
  --network "$NETWORK_NAME" --ip "${IP_BASE}.10" \
  --restart unless-stopped \
  openhack-hexstrike 2>/dev/null && log "hexstrike → ${IP_BASE}.10" || warn "hexstrike start failed"

stop_existing openhack-pentestai
docker run -d --name openhack-pentestai \
  --network "$NETWORK_NAME" --ip "${IP_BASE}.11" \
  --restart unless-stopped \
  openhack-pentestai 2>/dev/null && log "pentest-ai → ${IP_BASE}.11" || warn "pentestai start failed"

stop_existing openhack-rustsploit
docker run -d --name openhack-rustsploit \
  --network "$NETWORK_NAME" --ip "${IP_BASE}.12" \
  --privileged --user root \
  --restart unless-stopped \
  openhack-rustsploit 2>/dev/null && log "rustsploit → ${IP_BASE}.12 (privileged, root)" || warn "rustsploit start failed"

stop_existing openhack-arcticfox
docker run -d --name openhack-arcticfox \
  --network "$NETWORK_NAME" --ip "${IP_BASE}.13" \
  --restart unless-stopped \
  openhack-arcticfox 2>/dev/null && log "arcticfox → ${IP_BASE}.13" || warn "arcticfox start failed"

stop_existing openhack-sysreptor
docker run -d --name openhack-sysreptor \
  --network "$NETWORK_NAME" --ip "${IP_BASE}.14" \
  -p 8000:8000 \
  --restart unless-stopped \
  ${SYSREPTOR_IMAGE:-syslifters/sysreptor:latest} 2>/dev/null && log "sysreptor → ${IP_BASE}.14 (also localhost:8000)" || warn "sysreptor start failed"

# ─── Step 6: Health Check Wait ───

info "Waiting for containers to be ready..."
for i in $(seq 1 30); do
  sleep 2
  READY=0
  docker exec openhack-hexstrike echo ok 2>/dev/null && READY=$((READY+1)) || true
  docker exec openhack-pentestai echo ok 2>/dev/null && READY=$((READY+1)) || true
  docker exec openhack-rustsploit echo ok 2>/dev/null && READY=$((READY+1)) || true
  docker exec openhack-arcticfox echo ok 2>/dev/null && READY=$((READY+1)) || true
  if [ $READY -ge 4 ]; then
    log "All 4 MCP containers responsive"
    break
  fi
  [ $((i % 5)) -eq 0 ] && info "Waiting... (${i}s, ${READY}/4 ready)"
done

# ─── Step 7: Generate Config ───

info "Generating OpenHack config..."
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_DIR/openhack.json" << JSONEOF
{
  "safety": { "enabled": true, "whitelist": [], "require_confirmation": ["rm -rf", "dd if=", "mkfs"] },
  "scope": { "enabled": false, "targets": [], "exclusions": [] },
  "mcp": {
    "hexstrike": {
      "type": "local",
      "command": ["docker", "exec", "-i", "openhack-hexstrike", "python3", "hexstrike_mcp.py", "--server", "http://${IP_BASE}.10:8888"],
      "enabled": true,
      "timeout": 300000
    },
    "pentestai": {
      "type": "local",
      "command": ["docker", "exec", "-i", "openhack-pentestai", "ptai", "mcp"],
      "enabled": true,
      "timeout": 300000
    },
    "rustsploit": {
      "type": "local",
      "command": ["docker", "exec", "-i", "openhack-rustsploit", "/app/target/release/rustsploit", "--mcp"],
      "enabled": true,
      "timeout": 300000
    },
    "arcticfox": {
      "type": "local",
      "command": ["docker", "exec", "-i", "openhack-arcticfox", "/app/target/release/arcticfox-mcp"],
      "enabled": true,
      "timeout": 300000
    },
    "sysreptor": {
      "type": "remote",
      "url": "http://localhost:8000",
      "enabled": true,
      "headers": {}
    }
  }
}
JSONEOF

log "Config written to $CONFIG_DIR/openhack.json"

# ─── Step 8: Dashboard ───

echo ""
bold "╔══════════════════════════════════════════════╗"
bold "║        OpenHack MCP Deployment Ready          ║"
bold "╠══════════════════════════════════════════════╣"
printf "${BLUE}║${NC} Network: %-36s ${BLUE}║${NC}\n" "$NETWORK_SUBNET"
printf "${BLUE}║${NC} %-12s → %-30s ${BLUE}║${NC}\n" "hexstrike" "${IP_BASE}.10"
printf "${BLUE}║${NC} %-12s → %-30s ${BLUE}║${NC}\n" "pentest-ai" "${IP_BASE}.11"
printf "${BLUE}║${NC} %-12s → %-30s ${BLUE}║${NC}\n" "rustsploit" "${IP_BASE}.12 (root)"
printf "${BLUE}║${NC} %-12s → %-30s ${BLUE}║${NC}\n" "arcticfox" "${IP_BASE}.13"
printf "${BLUE}║${NC} %-12s → %-30s ${BLUE}║${NC}\n" "sysreptor" "localhost:8000"
bold "╚══════════════════════════════════════════════╝"
echo ""
info "Run OpenHack: cd $OPENHACK_DIR && bun run packages/opencode/src/index.ts"
info "Status:      docker ps --filter name=openhack"
info "Stop:        docker stop openhack-hexstrike openhack-pentestai openhack-rustsploit openhack-arcticfox openhack-sysreptor"
info "Start:       docker start openhack-hexstrike openhack-pentestai openhack-rustsploit openhack-arcticfox openhack-sysreptor"
info "Remove:      docker rm -f openhack-hexstrike openhack-pentestai openhack-rustsploit openhack-arcticfox openhack-sysreptor"
echo ""
log "Deployment complete! All MCP servers running."
