#!/bin/bash
set -euo pipefail

# Log all output for debugging via: sudo cat /var/log/cloud-init-output.log
exec > >(tee /var/log/user-data.log) 2>&1
echo "=== Claude Code VM bootstrap started at $(date) ==="

# Create unprivileged user for running Claude Code
useradd -m -s /bin/bash claude-user

# Install system packages
yum install -y git tmux make gcc zip unzip tar

# Install Node.js 22 (LTS) — required for Claude Code
curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -
yum install -y nodejs

# Install Go 1.25 (ARM64) — required for Roxas builds and tests
GO_VERSION="1.25.3"
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" | tar -C /usr/local -xzf -
cat > /etc/profile.d/go.sh << 'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$HOME/go/bin
EOF

# Install Chromium dependencies (for go-rod headless browser E2E tests)
# go-rod auto-downloads its own Chromium binary, but needs these system libs
yum install -y \
  alsa-lib atk at-spi2-atk cups-libs libdrm libXcomposite \
  libXdamage libXrandr mesa-libgbm pango nss nss-util

# Install Claude Code CLI
npm install -g @anthropic-ai/claude-code

# Install GitHub CLI (ARM64)
GH_VERSION="2.65.0"
curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_arm64.rpm" -o /tmp/gh.rpm
yum install -y /tmp/gh.rpm && rm /tmp/gh.rpm

# Ensure SSM Agent is running (Amazon Linux 2023 has it pre-installed)
systemctl enable amazon-ssm-agent && systemctl start amazon-ssm-agent

# Set up claude-user SSH authorized_keys from ec2-user
mkdir -p /home/claude-user/.ssh
cp /home/ec2-user/.ssh/authorized_keys /home/claude-user/.ssh/
chown -R claude-user:claude-user /home/claude-user/.ssh
chmod 700 /home/claude-user/.ssh
chmod 600 /home/claude-user/.ssh/authorized_keys

# Set up Go workspace for claude-user
su - claude-user -c 'mkdir -p ~/go/bin'

# Create helper script for starting remote-control in tmux
cat > /home/claude-user/start-claude.sh << 'SCRIPT'
#!/bin/bash
# Start a tmux session with Claude Code remote-control
tmux new-session -d -s claude 'claude remote-control --verbose' 2>/dev/null || \
  echo "Session 'claude' already exists. Attach with: tmux attach -t claude"
echo "Claude remote-control started in tmux session 'claude'"
echo "Attach with: tmux attach -t claude"
SCRIPT
chmod +x /home/claude-user/start-claude.sh
chown claude-user:claude-user /home/claude-user/start-claude.sh

echo "=== Claude Code VM bootstrap completed at $(date) ==="
