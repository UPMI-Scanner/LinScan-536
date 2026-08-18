#!/usr/bin/env bash
# ==============================================================================
# LinScan-536: Automated Quality Check & Git Build Verification Script
# ==============================================================================

set -euo pipefail

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}  LinScan-536: Repository Validation & Rebuild     ${NC}"
echo -e "${CYAN}====================================================${NC}"

# 1. Verify working directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
echo -e "${GREEN}✓ Working directory:${NC} $PROJECT_DIR"

# 2. Check essential system dependencies
echo -e "\n${YELLOW}[1/5] Checking system dependencies...${NC}"
for cmd in python3 ffmpeg git; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $cmd is installed."
    else
        echo -e "  ${RED}✗ Error: $cmd is not installed.${NC}"
        exit 1
    fi
done

# 3. Check Python library dependencies
echo -e "\n${YELLOW}[2/5] Checking Python packages...${NC}"
python3 -c "import tkinter, serial" 2>/dev/null && {
    echo -e "  ${GREEN}✓${NC} tkinter and pyserial are available."
} || {
    echo -e "  ${RED}✗ Error: Required Python libraries missing. Run: sudo apt install python3-tk python3-serial${NC}"
    exit 1
}

# 4. Clean Python bytecode and temporary caches
echo -e "\n${YELLOW}[3/5] Cleaning bytecode caches...${NC}"
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo -e "  ${GREEN}✓${NC} Cached bytecode removed."

# 5. Validate Python syntax
echo -e "\n${YELLOW}[4/5] Running Python bytecode compilation check...${NC}"
python3 -m py_compile linscan_536.py
echo -e "  ${GREEN}✓ linscan_536.py compiled with zero syntax errors.${NC}"

# 6. Apply executable permissions
echo -e "\n${YELLOW}[5/5] Enforcing file permissions...${NC}"
chmod +x linscan_536.py rebuild.sh
echo -e "  ${GREEN}✓${NC} Execution flags set."

# 7. Git repository status summary
echo -e "\n${CYAN}====================================================${NC}"
echo -e "${CYAN}  Git Status Summary                                ${NC}"
echo -e "${CYAN}====================================================${NC}"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git status -s
    echo -e "\n${GREEN}Ready to commit. Suggested command:${NC}"
    echo -e "  git add ."
    echo -e "  git commit -m \"Fix activity logging, UID tracking, and display state machine\""
    echo -e "  git push origin main"
else
    echo -e "${YELLOW}Notice: Current folder is not initialized as a git repository.${NC}"
fi
