#!/bin/bash
# Complete setup script for VAPT Recon Tool

echo "🔧 Setting up Advanced Web Reconnaissance Tool..."

# Create directories
mkdir -p modules utils wordlists reports

# Create virtual environment
python3 -m venv recon_env
source recon_env/bin/activate

# Install requirements
pip install --upgrade pip
pip install -r requirements.txt

# Download wordlist
cd wordlists
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O common.txt
cd ..

# Create .env from example
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Please edit .env file with your API keys"
fi

echo "✅ Setup complete!"
echo ""
echo "📝 Next steps:"
echo "1. Edit .env file: nano .env"
echo "2. Add your API keys (free tiers available at shodan.io, virustotal.com, etc.)"
echo "3. Run: python3 main.py example.com --mode passive"
echo ""
echo "🔒 IMPORTANT: Only scan targets you own or have written permission to test!"
