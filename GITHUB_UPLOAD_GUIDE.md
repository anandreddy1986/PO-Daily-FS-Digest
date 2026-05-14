# GitHub Upload Guide

## Files to Commit (Safe for Public Repo)

✅ **Core Scripts**
- `daily_po_report.py` - Main automation script
- `send_project_summary.py` - Project summary emailer

✅ **Configuration Templates** (No sensitive data)
- `.mcp.json.example` - Jira MCP configuration template
- `email_config.json.example` - Email settings template
- `.env.example` - Environment variables template

✅ **Documentation**
- `README.md` - Comprehensive project documentation
- `LICENSE` - MIT License
- `PROJECT_SUMMARY.pdf` - Project overview (PDF)
- `PROJECT_SUMMARY.html` - Project overview (HTML)

✅ **Git Configuration**
- `.gitignore` - Excludes sensitive files

## Files to Keep Local (Excluded by .gitignore)

🔒 **Credentials & Secrets**
- `.mcp.json` - Contains Jira API tokens
- `.env` - Contains SMTP passwords
- `email_config.json` - Contains actual email addresses

🔒 **Runtime Files**
- `.last_report_sent.txt` - Timestamp tracking
- `logs/` - Log files directory
- `__pycache__/` - Python cache

🔒 **Claude Code Settings**
- `.claude/settings.local.json` - Local Claude settings
- `.claude/projects/` - Project-specific Claude data
- `.claude/logs/` - Claude logs

## Upload Steps

1. **Initialize Git** (if not already done)
   ```bash
   git init
   git add .
   ```

2. **Review Files to Commit**
   ```bash
   git status
   ```
   
   Verify only safe files are staged (no .mcp.json, .env, email_config.json)

3. **Commit Changes**
   ```bash
   git commit -m "Initial commit: FS Teams Daily Digest automation"
   ```

4. **Add Remote**
   ```bash
   git remote add origin https://github.com/anandreddy1986/PO-Daily-FS-Digest.git
   ```

5. **Push to GitHub**
   ```bash
   git branch -M main
   git push -u origin main
   ```

## Post-Upload Setup for New Users

After cloning the repository, users should:

1. Copy template files:
   ```bash
   cp .mcp.json.example .mcp.json
   cp email_config.json.example email_config.json
   cp .env.example .env
   ```

2. Edit configuration files with their credentials:
   - `.mcp.json` - Add Jira API token
   - `email_config.json` - Add email address and team mappings
   - `.env` - Add SMTP password (if using Gmail fallback)

3. Test the script:
   ```bash
   python3 daily_po_report.py --dry-run
   ```

## Security Note

⚠️ **Never commit files containing:**
- API tokens or passwords
- Email addresses
- Internal server names (beyond what's already in templates)
- Personal credentials

The `.gitignore` file protects against accidental commits, but always verify with `git status` before pushing.
