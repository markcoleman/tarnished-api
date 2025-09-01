#!/bin/bash
set -e

echo "🔧 Setting up Tarnished API development environment..."

# Ensure cargo is available and working
source ~/.cargo/env 2>/dev/null || true

# Add cargo bin to PATH for current session
export PATH="$HOME/.cargo/bin:$PATH"

# Add cargo bin to shell profiles if not already present
grep -qxF 'export PATH="$HOME/.cargo/bin:$PATH"' ~/.bashrc || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
grep -qxF 'export PATH="$HOME/.cargo/bin:$PATH"' ~/.zshrc 2>/dev/null || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true

# For global access, also add to profile
grep -qxF 'export PATH="$HOME/.cargo/bin:$PATH"' ~/.profile 2>/dev/null || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile 2>/dev/null || true

# Install Rust components
echo "📦 Installing Rust components..."
rustup component add clippy rustfmt

# Install just task runner specifically
echo "🛠️ Installing just task runner..."
if ! command -v just &> /dev/null; then
    echo "Installing just..."
    cargo install just
else
    echo "✅ just is already installed: $(just --version)"
fi

# Install other development tools
echo "🛠️ Installing additional development tools..."
for tool in cargo-watch cargo-audit cargo-outdated; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Installing $tool..."
        cargo install "$tool"
    else
        echo "✅ $tool is already installed"
    fi
done

# Verify just installation and add to global path if needed
echo "✅ Verifying just installation..."
if command -v just &> /dev/null; then
    JUST_PATH=$(which just)
    echo "✅ just installed successfully at: $JUST_PATH"
    echo "✅ just version: $(just --version)"
    
    # Create a symlink in /usr/local/bin for global access (if we have permissions)
    if [ -w /usr/local/bin ] && [ ! -e /usr/local/bin/just ]; then
        sudo ln -sf "$JUST_PATH" /usr/local/bin/just 2>/dev/null || echo "Note: Could not create global symlink, but just should work in shell"
    fi
    
    # Run project setup
    echo "🚀 Running project setup..."
    just setup || echo "⚠️ Note: just setup encountered issues, but just is available for manual use"
else
    echo "❌ just installation failed"
    exit 1
fi

echo "✅ Development environment setup complete!"
echo "💡 If 'just' command is not found, try running: source ~/.bashrc"