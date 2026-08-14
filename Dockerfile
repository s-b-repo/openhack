FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENHACK_MCP_DIR=/opt/openhack-mcp
ENV RUSTSPLOIT_PATH=/opt/openhack-mcp/rustsploit/target/release/rustsploit
ENV ARCTICFOX_PATH=/opt/openhack-mcp/arcticfox-c3/target/release/arcticfox-mcp
ENV HEXSTRIKE_PATH=/opt/openhack-mcp/hexstrike-ai

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git build-essential pkg-config libssl-dev cmake \
    python3 python3-pip python3-venv \
    nmap nuclei sqlmap gobuster ffuf hydra john hashcat \
    amass subfinder dnsenum metasploit-framework \
    dirsearch nikto wpscan whatweb dalfox \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://bun.sh/install | bash && \
    cp /root/.bun/bin/bun /usr/local/bin/bun && \
    chmod +x /usr/local/bin/bun

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    cp /root/.cargo/bin/cargo /usr/local/bin/cargo && \
    cp /root/.cargo/bin/rustc /usr/local/bin/rustc

COPY . /opt/openhack
WORKDIR /opt/openhack

RUN bun install --frozen-lockfile 2>/dev/null || bun install

RUN mkdir -p /opt/openhack-mcp

RUN git clone --depth 1 https://github.com/0x4m4/hexstrike-ai.git /opt/openhack-mcp/hexstrike-ai && \
    cd /opt/openhack-mcp/hexstrike-ai && \
    python3 -m venv hexstrike-env && \
    . hexstrike-env/bin/activate && \
    pip install -r requirements.txt

RUN pip3 install ptai

RUN git clone --depth 1 https://github.com/s-b-repo/rustsploit.git /opt/openhack-mcp/rustsploit && \
    cd /opt/openhack-mcp/rustsploit && \
    cargo build --release

RUN git clone --depth 1 https://github.com/s-b-repo/arcticfox-c3.git /opt/openhack-mcp/arcticfox-c3 && \
    cd /opt/openhack-mcp/arcticfox-c3 && \
    cargo build --release

RUN mkdir -p /root/.config/openhack /root/.local/share/openhack
COPY .openhack/openhack.jsonc /root/.config/openhack/openhack.json

ENV PATH="/opt/openhack/node_modules/.bin:${PATH}"

ENTRYPOINT ["bun", "run", "/opt/openhack/packages/openhack-cli/src/index.ts"]
