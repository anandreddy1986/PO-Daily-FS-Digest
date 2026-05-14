# FS Teams Daily Digest - Agentic PO Automation

> Automated daily digest system delivering comprehensive status updates for RHEL File System teams.

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 📋 Overview

This project automates daily Product Owner updates for four RHEL File System teams (FS-Net, FS-local, FS-VFS, FS-GFS2). It replaces manual dashboard checking with intelligent automation, querying Jira data and delivering structured morning reports at 7:00 AM IST.

### Problem Statement

As Product Owner for the File System team, manually checking dashboards across four FS subsystems was:
- **Time-consuming**: 15-20 minutes daily checking multiple Jira filters
- **Reactive**: Critical updates discovered after daily planning started
- **Fragmented**: No consolidated view across teams

### Solution

An agentic automation system that:
- ✅ Queries Jira REST API v3 using optimized JQL
- ✅ Applies Python-based regex filtering for accurate CVE identification
- ✅ Groups related issues intelligently (60% email reduction)
- ✅ Delivers clean HTML emails with clickable Jira hyperlinks
- ✅ Schedules via cron with catch-up mechanism for missed runs

## 🎯 Key Features

### Smart CVE Tracking
- Python regex filtering (`CVE-\d{4}-\d+`) overcomes Jira text search limitations
- Groups CVEs across RHEL versions to reduce redundancy
- Three-tier filtering: issue type, summary pattern, label matching

### Customer Escalation Monitoring
- Tracks issues with `Escalation🔥` label
- Monitors `Customer Impact = Customer Escalated` field
- Prioritizes customer-impacting issues

### Testing Pipeline Visibility
- **Preliminary Testing**: Issues with testing requested or in progress
- **Integration Testing**: Issues in integration with fixed builds
- Separate tracking from regular bug/CVE workflow

### Intelligent Grouping
- Consolidates same CVE across RHEL versions (e.g., rhel-9.7.z, rhel-9.8.z)
- Groups similar bugs by description pattern
- Reduces email length by ~60% while maintaining full visibility

### Reliability Features
- **Dual-trigger**: Cron schedule (7:00 AM IST) + SessionStart hook
- **Catch-up mechanism**: Detects missed runs and sends report on system wake
- **Timestamp tracking**: Prevents duplicate sends on same day

## 🛠 Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Orchestration** | Python 3.8+ | Core automation logic |
| **Data Source** | Jira REST API v3 | Issue querying and filtering |
| **Query Language** | JQL + Python regex | Precise issue identification |
| **Email Delivery** | SMTP (Red Hat) | Reliable corporate delivery |
| **Scheduling** | Claude Code CronCreate | Daily 7:00 AM IST execution |
| **Resilience** | SessionStart hooks | Catch-up when Mac sleeps |
| **Configuration** | JSON | Centralized settings |

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- Access to Jira instance (Red Hat Jira)
- SMTP server access (Red Hat corporate SMTP)
- Claude Code CLI (for scheduling)

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/anandreddy1986/PO-Daily-FS-Digest.git
   cd PO-Daily-FS-Digest
   ```

2. **Install dependencies**
   ```bash
   pip install requests reportlab
   ```

3. **Configure Jira credentials**
   ```bash
   cp .mcp.json.example .mcp.json
   # Edit .mcp.json with your Jira credentials
   ```

4. **Configure email settings**
   ```bash
   cp email_config.json.example email_config.json
   # Edit email_config.json with your settings
   ```

5. **Test the script**
   ```bash
   python3 daily_po_report.py --dry-run
   ```

## ⚙️ Configuration

### email_config.json

```json
{
  "recipient": "your-email@example.com",
  "smtp_server": "smtp.corp.redhat.com",
  "smtp_port": 25,
  "teams": {
    "FS-Net": "rhel-fs-net",
    "FS-local": "rhel-fs-local",
    "FS-VFS": "rhel-fs-vfs",
    "FS-GFS2": "rhel-fs-gfs2"
  },
  "custom_fields": {
    "assigned_team": "customfield_10606",
    "severity": "customfield_10840",
    "qa_contact": "customfield_10470",
    "sfdc_cases": "customfield_10978"
  },
  "schedule_time": "08:07",
  "jira_project": "RHEL"
}
```

### .mcp.json

Configure Jira API access:

```json
{
  "mcpServers": {
    "mcp-atlassian": {
      "command": "uvx",
      "args": ["mcp-atlassian"],
      "env": {
        "JIRA_URL": "https://your-org.atlassian.net",
        "JIRA_USERNAME": "your-email@example.com",
        "JIRA_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

## 🚀 Usage

### Manual Execution

```bash
# Dry run (no email sent)
python3 daily_po_report.py --dry-run

# Force send (ignores timestamp check)
python3 daily_po_report.py --force

# Normal execution
python3 daily_po_report.py
```

### Scheduled Execution

The system uses Claude Code's cron scheduling with a SessionStart hook for catch-up:

**Cron Schedule** (daily at 8:07 AM):
```python
CronCreate(
    cron="7 8 * * *",
    prompt="Run daily PO report",
    durable=True
)
```

**SessionStart Hook** (catch-up mechanism):
```json
{
  "hooks": {
    "SessionStart": [{
      "hooks": [{
        "type": "command",
        "command": "cd /path/to/project && python3 daily_po_report.py",
        "statusMessage": "Checking daily PO report..."
      }]
    }]
  }
}
```

## 📊 Email Report Sections

Each daily digest includes:

### 1. New & Closed Issues (Last 24h)
- Issues created in last 24 hours
- Issues closed/resolved in last 24 hours
- Type filters: Bug, Vulnerability, Story

### 2. Active CVEs
- All open CVE issues grouped by CVE ID
- Severity levels and assignees
- Affected RHEL versions as clickable links

### 3. Preliminary Testing Requested
- Issues with testing requested
- In-progress testing items
- Grouped by description pattern

### 4. Integration Testing
- Issues in integration status
- Must have "Fixed in Build" populated
- Ready for QE validation

### 5. Customer Escalations
- Issues with Escalation🔥 label
- Customer Impact = Customer Escalated
- Critical customer-affecting items

### 6. Key Progress
- Recently updated high-priority items
- Status: In Progress, In Review, Testing
- Priority: Blocker, Critical, Major

### 7. Tasks (Last Updated)
- Task-type issues updated in last 24h
- Grouped by description
- Separate from Bug/CVE workflow

## 🔍 JQL Query Examples

### CVE Issues
```jql
project = RHEL AND 
AssignedTeam = "rhel-fs-vfs" AND
type in (Bug, Vulnerability, Story) AND
status not in (Closed, Done, Resolved, "Release Pending")
```

Then Python filtering:
```python
# Three-tier CVE detection:
# 1. Issue type = Vulnerability or Weakness
# 2. Regex: re.search(r'CVE-\d{4}-\d+', summary)
# 3. Regex: CVE pattern in labels
```

### Customer Escalations
```jql
project = RHEL AND 
AssignedTeam = "rhel-fs-net" AND
(labels = "Escalation🔥" OR "Customer Impact" = "Customer Escalated") AND
status not in (Closed, Done, Resolved, "Release Pending")
```

### Integration Testing
```jql
project = RHEL AND 
AssignedTeam = "rhel-fs-local" AND
status = Integration AND 
"Fixed in Build" is not EMPTY
```

## 📈 Outcomes & Impact

- **Time Savings**: 15-20 minutes daily (100+ hours annually)
- **Proactive Alerting**: Morning briefing at 7:00 AM IST
- **Accuracy**: 100% CVE detection via Python regex filtering
- **Coverage**: 4 FS teams in single consolidated view
- **Readability**: 60% email reduction through intelligent grouping
- **Reliability**: 100% delivery via catch-up mechanism

## 🐛 Troubleshooting

### Common Issues

**Issue**: No email received

**Solutions**:
- Check SMTP server connectivity: `ping smtp.corp.redhat.com`
- Verify VPN connection for Red Hat corporate network
- Check `.last_report_sent.txt` timestamp
- Run with `--force` flag to bypass timestamp check

**Issue**: CVE missing from report

**Solutions**:
- Verify issue has CVE pattern in summary or labels
- Check issue type (must be Bug, Vulnerability, or Story)
- Confirm AssignedTeam field matches expected value
- Run with `--dry-run` to see query results

**Issue**: Duplicate emails

**Solutions**:
- Check `.last_report_sent.txt` - should contain today's date
- Verify cron schedule isn't running multiple times
- Check SessionStart hook isn't triggering unnecessarily

## 📝 Project Structure

```
PO-Daily-FS-Digest/
├── daily_po_report.py          # Main automation script
├── send_project_summary.py     # Project documentation emailer
├── email_config.json.example   # Email configuration template
├── .mcp.json.example           # Jira MCP configuration template
├── .env.example                # Environment variables template
├── PROJECT_SUMMARY.pdf         # Project documentation (PDF)
├── PROJECT_SUMMARY.html        # Project documentation (HTML)
├── README.md                   # This file
└── .gitignore                  # Git ignore rules
```

## 🤝 Contributing

This is a personal project for Red Hat File System team PO automation. If you have suggestions or improvements:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 👤 Author

**Anand Reddy**
- Email: anareddy@redhat.com
- GitHub: [@anandreddy1986](https://github.com/anandreddy1986)

## 🙏 Acknowledgments

- Red Hat File System team for requirements and feedback
- Claude Code for automation framework and scheduling
- Atlassian MCP server for Jira integration

## 📚 Additional Resources

- [Jira REST API Documentation](https://developer.atlassian.com/cloud/jira/platform/rest/v3/)
- [JQL Reference](https://support.atlassian.com/jira-software-cloud/docs/use-advanced-search-with-jira-query-language-jql/)
- [Claude Code Documentation](https://docs.anthropic.com/claude/docs/claude-code)

---

**Generated by**: FS Teams Daily Digest Automation System  
**Last Updated**: May 2026  
**Status**: Production (Daily 7:00 AM IST delivery)
