#!/usr/bin/env python3
"""
Daily Product Owner Report Generator
Sends daily email updates for FS teams (FS-Net, FS-local, FS-VFS, FS-GFS2)

Features:
- Scheduled daily at 7:00 AM IST
- Smart catch-up: sends on first run if today's report was missed
- Never sends twice in one day
"""

import json
import os
import sys
import argparse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from pathlib import Path
import requests
from requests.auth import HTTPBasicAuth


class JiraClient:
    """Jira API client for querying issues"""

    def __init__(self, url, username, api_token):
        self.url = url.rstrip('/')
        self.auth = HTTPBasicAuth(username, api_token)
        self.headers = {"Accept": "application/json"}

    def search_issues(self, jql, fields=None, max_results=50):
        """Search Jira issues using JQL"""
        endpoint = f"{self.url}/rest/api/3/search/jql"

        params = {
            "jql": jql,
            "maxResults": max_results,
            "fields": ",".join(fields) if fields else "summary,status,priority,assignee,created,updated"
        }

        try:
            response = requests.get(endpoint, headers=self.headers, auth=self.auth, params=params)
            response.raise_for_status()
            result = response.json()
            if result is None:
                return {"issues": [], "total": 0}
            return result
        except Exception as e:
            print(f"ERROR in search_issues: {str(e)}")
            print(f"JQL: {jql}")
            return {"issues": [], "total": 0}


class POReportGenerator:
    """Generates daily PO reports for FS teams"""

    LAST_SENT_FILE = ".last_report_sent.txt"

    def __init__(self, config_path="email_config.json"):
        self.config = self._load_config(config_path)
        self.jira = self._init_jira_client()
        self.custom_fields = self.config.get("custom_fields", {})
        self.script_dir = Path(__file__).parent

    def _load_config(self, config_path):
        """Load configuration from JSON file"""
        with open(config_path, 'r') as f:
            return json.load(f)

    def _init_jira_client(self):
        """Initialize Jira client from .mcp.json"""
        mcp_config_path = Path(__file__).parent / ".mcp.json"
        with open(mcp_config_path, 'r') as f:
            mcp_config = json.load(f)

        jira_env = mcp_config["mcpServers"]["mcp-atlassian"]["env"]
        return JiraClient(
            jira_env["JIRA_URL"],
            jira_env["JIRA_USERNAME"],
            jira_env["JIRA_API_TOKEN"]
        )

    def get_new_issues(self, team_value):
        """Get issues created in last 24 hours for a team (Bug, Vulnerability, Story only)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND type in (Bug, Vulnerability, Story) AND created >= -24h'
        result = self.jira.search_issues(jql, max_results=100)
        return result.get("issues", [])

    def get_closed_issues(self, team_value):
        """Get issues closed in last 24 hours for a team (Bug, Vulnerability, Story only)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND type in (Bug, Vulnerability, Story) AND status changed to (Closed, Done, Resolved) DURING (-24h, now())'
        result = self.jira.search_issues(jql, max_results=100)
        return result.get("issues", [])

    def get_weekend_new_issues(self, team_value):
        """Get issues created over the weekend (Friday-Sunday, i.e., 24h-72h ago)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND type in (Bug, Vulnerability, Story) AND created >= -72h AND created < -24h'
        result = self.jira.search_issues(jql, max_results=100)
        return result.get("issues", [])

    def get_weekend_closed_issues(self, team_value):
        """Get issues closed over the weekend (Friday-Sunday, i.e., 24h-72h ago)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND type in (Bug, Vulnerability, Story) AND status changed to (Closed, Done, Resolved) DURING (-72h, -24h)'
        result = self.jira.search_issues(jql, max_results=100)
        return result.get("issues", [])

    def get_cve_issues(self, team_value):
        """Get active CVE/security issues for a team

        Note: Gets all Bug/Vulnerability/Story issues and filters for CVEs in Python
        due to Jira text search limitations.
        """
        import re

        # Get all Bug/Vulnerability/Story issues for the team
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["summary", "status", "priority", "assignee", "created", "updated", "issuetype", self.custom_fields["severity"], "labels", "duedate"]
        result = self.jira.search_issues(jql, fields=fields, max_results=200)

        # Filter for CVE issues in Python
        cve_issues = []
        for issue in result.get("issues", []):
            is_cve = False

            # Check 1: Issue type is Vulnerability or Weakness
            if issue["fields"]["issuetype"]["name"] in ["Vulnerability", "Weakness"]:
                is_cve = True

            # Check 2: Summary contains CVE pattern (CVE-YYYY-XXXXX)
            if re.search(r'CVE-\d{4}-\d+', issue["fields"]["summary"], re.IGNORECASE):
                is_cve = True

            # Check 3: Labels contain CVE pattern
            labels = issue["fields"].get("labels", [])
            for label in labels:
                if re.match(r'CVE-\d{4}-\d+', label, re.IGNORECASE):
                    is_cve = True
                    break

            if is_cve:
                cve_issues.append(issue)

        return cve_issues

    def get_prelim_testing_requested(self, team_value):
        """Get issues with Preliminary Testing criteria"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 ("Preliminary Testing" = Requested OR status = "In Progress" AND ("Preliminary Testing" = Requested OR issuetype = Task AND labels = KWF:Task)) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["summary", "status", "priority", "assignee", "updated", "labels"]
        result = self.jira.search_issues(jql, fields=fields, max_results=100)

        return result.get("issues", [])

    def get_integration_testing(self, team_value):
        """Get issues with Status = Integration and Fixed in Build is not empty"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 status = Integration AND "Fixed in Build" is not EMPTY'''

        fields = ["summary", "status", "priority", "assignee", "updated"]
        result = self.jira.search_issues(jql, fields=fields, max_results=100)

        return result.get("issues", [])

    def get_customer_escalations(self, team_value):
        """Get customer escalations (Escalation🔥 label OR Customer Impact = Customer Escalated)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 (labels = "Escalation🔥" OR "Customer Impact" = "Customer Escalated") AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["summary", "status", "priority", "assignee", "updated", self.custom_fields["sfdc_cases"], self.custom_fields["customer_impact"], "labels"]
        result = self.jira.search_issues(jql, fields=fields, max_results=100)

        return result.get("issues", [])

    def get_customer_bugs_new(self, team_value):
        """Get customer-related bugs in NEW status (SFDC cases, Customer Impact, or bugproxy reported)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status = "New" AND
                 ("{self.custom_fields['sfdc_cases']}" IS NOT EMPTY OR
                  "{self.custom_fields['customer_impact']}" IS NOT EMPTY OR
                  reporter = "bugproxy bugproxy")'''

        fields = ["summary", "status", "priority", "assignee", "created", "reporter",
                  self.custom_fields["sfdc_cases"], self.custom_fields["customer_impact"],
                  self.custom_fields["severity"]]
        result = self.jira.search_issues(jql, fields=fields, max_results=100)

        return result.get("issues", [])

    def get_waiting_on_mr_merge(self, team_value):
        """Get issues waiting on MR merge (Testable Builds exist but Preliminary Testing not started)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability) AND
                 status = "In Progress" AND
                 "Testable Builds" is not EMPTY AND
                 "Preliminary Testing" is EMPTY'''

        fields = ["summary", "status", "priority", "assignee", "updated", self.custom_fields["testable_builds"]]
        result = self.jira.search_issues(jql, fields=fields, max_results=100)

        return result.get("issues", [])

    def get_key_progress(self, team_value):
        """Get recently updated high-priority items showing progress (Bug, Vulnerability, Story only)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 priority in (Blocker, Critical, Major) AND
                 updated >= -24h AND
                 status in ("In Progress", "In Review", "Testing", "QE Review") AND
                 status not in ("Release Pending")'''

        result = self.jira.search_issues(jql, max_results=50)
        return result.get("issues", [])

    def get_tasks(self, team_value):
        """Get Task type issues updated in last 24h for a team"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = "{team_value}" AND
                 type = Task AND
                 updated >= -24h AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        result = self.jira.search_issues(jql, max_results=100)
        return result.get("issues", [])

    def group_issues_by_description(self, issues, include_severity=False):
        """Group issues by core description (works for CVEs, bugs, and tasks)"""
        import re
        grouped = {}

        for issue in issues:
            summary = issue["fields"]["summary"]

            # Remove prefixes like [KWF:kernel-rt], [Root Cause Analysis Task]:, [Upstream]:, [DEV Task]:, etc.
            clean_summary = re.sub(r'^\[.+?\]\s*:\s*', '', summary)  # Remove [Something]: prefix with colon
            clean_summary = re.sub(r'^\[.+?\]\s+', '', clean_summary)  # Remove [Something] prefix without colon

            # Extract CVE ID if present
            cve_match = re.search(r'(CVE-\d{4}-\d+)', clean_summary, re.IGNORECASE)

            # Extract version tag (e.g., [rhel-10.3])
            version_match = re.search(r'\[(rhel-[\d.z]+)\]', summary)
            version = version_match.group(1) if version_match else ""

            if cve_match:
                # CVE-based grouping
                cve_id = cve_match.group(1).upper()
                desc_match = re.search(r'CVE-\d{4}-\d+\s+(.+?)(?:\s+\[|$)', clean_summary, re.IGNORECASE)
                description = desc_match.group(1).strip() if desc_match else clean_summary
                group_key = cve_id
            else:
                # Non-CVE: group by description without version tag
                description = re.sub(r'\s*\[rhel-[\d.z]+\]', '', clean_summary).strip()
                group_key = f"DESC-{description[:50]}"  # Use first 50 chars as key

            if group_key not in grouped:
                grouped[group_key] = {
                    "description": description,
                    "issues": [],
                    "assignees": set(),
                    "is_cve": cve_match is not None,
                    "cve_id": cve_id if cve_match else None
                }

                if include_severity:
                    severity_field = issue["fields"].get(self.custom_fields["severity"])
                    grouped[group_key]["severity"] = severity_field.get("value", "N/A") if severity_field else "N/A"

            grouped[group_key]["issues"].append({
                "key": issue["key"],
                "version": version,
                "status": issue["fields"]["status"]["name"],
                "assignee": issue["fields"]["assignee"]["displayName"] if issue["fields"].get("assignee") else "Unassigned",
                "priority": issue["fields"]["priority"]["name"] if issue["fields"].get("priority") else "Undefined",
                "duedate": issue["fields"].get("duedate")
            })

            if issue["fields"].get("assignee"):
                grouped[group_key]["assignees"].add(issue["fields"]["assignee"]["displayName"])

        return grouped

    def group_cves(self, issues):
        """Group CVE issues by CVE ID - wrapper for backward compatibility"""
        return self.group_issues_by_description(issues, include_severity=True)

    def generate_table_format(self, grouped_data, section_type="cve"):
        """Generate HTML table for grouped issues

        Args:
            grouped_data: Dict from group_issues_by_description()
            section_type: Type of section (cve, prelim, integration, waiting, progress, tasks)
        """
        if not grouped_data:
            return ""

        # Common table styles (compressed)
        s = "padding:6px;border-bottom:"
        if section_type == "cve":
            table_style = f"""<table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:0.9em"><thead><tr style="background-color:#f0f0f0"><th style="{s}2px solid #ddd;text-align:left">CVE ID</th><th style="{s}2px solid #ddd;text-align:left">Description</th><th style="{s}2px solid #ddd;text-align:left">Severity</th><th style="{s}2px solid #ddd;text-align:left">Assignee</th><th style="{s}2px solid #ddd;text-align:center"># Ver</th><th style="{s}2px solid #ddd;text-align:left">Versions</th><th style="{s}2px solid #ddd;text-align:left">Earliest Due</th></tr></thead><tbody>"""
        else:
            table_style = f"""<table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:0.9em"><thead><tr style="background-color:#f0f0f0"><th style="{s}2px solid #ddd;text-align:left">Bug/CVE</th><th style="{s}2px solid #ddd;text-align:left">Description</th><th style="{s}2px solid #ddd;text-align:left">Assignee</th><th style="{s}2px solid #ddd;text-align:center"># Ver</th><th style="{s}2px solid #ddd;text-align:left">Versions</th></tr></thead><tbody>"""

        html_rows = []

        # Sort by earliest due date for CVEs (overdue first), otherwise by description
        if section_type == "cve":
            def get_earliest_due(group_item):
                """Get earliest due date, handling None values"""
                due_dates = [issue.get('duedate') for issue in group_item[1]['issues'] if issue.get('duedate')]
                return min(due_dates) if due_dates else '9999-99-99'

            sorted_items = sorted(grouped_data.items(), key=get_earliest_due)
        else:
            sorted_items = list(grouped_data.items())

        for idx, (group_key, group_data) in enumerate(sorted_items):
            # Alternate row colors
            row_bg = "#ffffff" if idx % 2 == 0 else "#f9f9f9"

            # Get data
            description = group_data["description"]
            if len(description) > 80:
                description = description[:77] + "..."

            assignees_list = ", ".join(sorted(group_data['assignees'])) if group_data['assignees'] else "Unassigned"
            num_versions = len(group_data["issues"])

            # Build version links
            version_links = []
            for issue_data in group_data["issues"][:5]:  # Show first 5 versions
                issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                version_links.append(
                    f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                )

            if num_versions > 5:
                version_links.append(f"<span style='color: #999;'>+{num_versions - 5} more</span>")

            versions_str = ", ".join(version_links)

            # CVE specific columns
            if section_type == "cve":
                cve_id = group_data.get("cve_id", "")
                severity = group_data.get("severity", "N/A")

                # Get first issue key for CVE link
                first_issue_key = group_data['issues'][0]['key'] if group_data['issues'] else ""
                first_issue_url = f"{self.jira.url}/browse/{first_issue_key}" if first_issue_key else "#"

                # Build CVE ID display with link
                if cve_id:
                    cve_display = f'<a href="{first_issue_url}" style="color: #d73027; text-decoration: none; font-weight: bold;">{cve_id}</a>'
                else:
                    cve_display = f'<a href="{first_issue_url}" style="color: #666; text-decoration: none;">Non-CVE</a>'

                # Get earliest due date
                due_dates = [issue.get('duedate') for issue in group_data['issues'] if issue.get('duedate')]
                if due_dates:
                    earliest_due = min(due_dates)

                    # Check if overdue
                    from datetime import datetime
                    try:
                        due_dt = datetime.strptime(earliest_due, "%Y-%m-%d")
                        now_dt = datetime.now()
                        is_overdue = due_dt < now_dt

                        if is_overdue:
                            due_display = f'<span style="color: #d73027; font-weight: bold;">{earliest_due} ⚠️ OVERDUE</span>'
                        else:
                            days_left = (due_dt - now_dt).days
                            if days_left <= 7:
                                due_display = f'<span style="color: #e67e22; font-weight: bold;">{earliest_due} ({days_left}d)</span>'
                            else:
                                due_display = earliest_due
                    except:
                        due_display = earliest_due
                else:
                    due_display = "-"

                # Severity color coding
                if severity == "Critical":
                    severity_display = f'<span style="color: #d73027; font-weight: bold;">{severity}</span>'
                elif severity == "Important":
                    severity_display = f'<span style="color: #e67e22; font-weight: bold;">{severity}</span>'
                elif severity == "Moderate":
                    severity_display = f'<span style="color: #f39c12;">{severity}</span>'
                else:
                    severity_display = severity

                c = "padding:6px;border-bottom:1px solid #eee"
                html_rows.append(f"""<tr style="background-color:{row_bg}"><td style="{c}">{cve_display}</td><td style="{c}">{description}</td><td style="{c}">{severity_display}</td><td style="{c}">{assignees_list}</td><td style="{c};text-align:center">{num_versions}</td><td style="{c};font-size:0.85em">{versions_str}</td><td style="{c}">{due_display}</td></tr>""")
            else:
                # Non-CVE sections - show actual issue key or CVE ID
                first_issue_key = group_data['issues'][0]['key'] if group_data['issues'] else ""
                first_issue_url = f"{self.jira.url}/browse/{first_issue_key}" if first_issue_key else "#"

                issue_id = group_data.get("cve_id", "")
                if issue_id:
                    # Has CVE ID
                    issue_display = f'<a href="{first_issue_url}" style="color:#8e44ad;text-decoration:none;font-weight:bold">{issue_id}</a>'
                else:
                    # No CVE, show issue key as link with "Bug"/"Task" label
                    issue_type_label = "Bug" if num_versions == 1 else "Bug"  # Default to Bug
                    issue_display = f'<a href="{first_issue_url}" style="color:#666;text-decoration:none;font-weight:bold">{first_issue_key}</a>'

                c = "padding:6px;border-bottom:1px solid #eee"
                html_rows.append(f"""<tr style="background-color:{row_bg}"><td style="{c}">{issue_display}</td><td style="{c}">{description}</td><td style="{c}">{assignees_list}</td><td style="{c};text-align:center">{num_versions}</td><td style="{c}">{versions_str}</td></tr>""")

        table_style += "".join(html_rows)
        table_style += """</tbody></table>"""
        return table_style

    def format_issue_line(self, issue, include_fields=None):
        """Format a single issue as an HTML line"""
        key = issue["key"]
        summary = issue["fields"]["summary"]
        issue_url = f"{self.jira.url}/browse/{key}"

        parts = [f'<strong><a href="{issue_url}" style="color: #3498db; text-decoration: none;">{key}</a></strong>: {summary}']

        if include_fields:
            details = []
            if "status" in include_fields and "status" in issue["fields"]:
                status = issue["fields"]["status"]["name"]
                details.append(f"Status: {status}")

            if "priority" in include_fields and issue["fields"].get("priority"):
                priority = issue["fields"]["priority"]["name"]
                details.append(f"Priority: {priority}")

            if "assignee" in include_fields and issue["fields"].get("assignee"):
                assignee = issue["fields"]["assignee"]["displayName"]
                details.append(f"Assignee: {assignee}")

            if "severity" in include_fields and issue["fields"].get(self.custom_fields["severity"]):
                severity = issue["fields"][self.custom_fields["severity"]].get("value", "N/A")
                details.append(f"Severity: {severity}")

            if "sfdc_cases" in include_fields and issue["fields"].get(self.custom_fields["sfdc_cases"]):
                sfdc = issue["fields"][self.custom_fields["sfdc_cases"]]
                details.append(f"SFDC Cases: {sfdc}")

            if "updated" in include_fields and "updated" in issue["fields"]:
                updated = issue["fields"]["updated"]
                updated_dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                time_ago = self._time_ago(updated_dt)
                details.append(f"Last Updated: {time_ago}")

            if details:
                parts.append(f'<br><span style="color: #666; font-size: 0.9em;">{" | ".join(details)}</span>')

        return "  " + " ".join(parts)

    def _time_ago(self, dt):
        """Convert datetime to relative time string"""
        now = datetime.now(dt.tzinfo)
        diff = now - dt

        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds >= 3600:
            return f"{diff.seconds // 3600}h ago"
        else:
            return f"{diff.seconds // 60}m ago"

    def generate_team_section(self, team_name, team_value):
        """Generate HTML section for one FS team"""
        html = [f"""<div style="margin-bottom:40px;border-left:5px solid #2c5aa0;padding:25px;border-radius:8px;background:linear-gradient(to right,#f8f9fa,#ffffff);box-shadow:0 2px 4px rgba(0,0,0,0.1)"><h2 style="color:#2c5aa0;border-bottom:3px solid #2c5aa0;padding-bottom:12px;margin-top:0;font-size:1.4em">📊 {team_name}</h2>"""]

        # Section 1: New & Closed Issues
        new_issues = self.get_new_issues(team_value)
        closed_issues = self.get_closed_issues(team_value)

        # Group new issues by description for better readability
        new_groups = self.group_issues_by_description(new_issues, include_severity=True)
        html.append(f'<h3 style="color:#1976d2;margin-top:20px">📌 New Issues (Last 24h): {len(new_groups)}</h3>')
        if new_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in new_groups.items():
                # Issue header with description and assignee in one line
                assignees_list = ", ".join(sorted(group_data['assignees'])) if group_data['assignees'] else "Unassigned"

                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #e74c3c;">{group_data["cve_id"]}</strong>: {group_data["description"]} ({assignees_list})')
                else:
                    html.append(f'<li>{group_data["description"]} ({assignees_list})')

                # Show severity only if NOT N/A
                severity = group_data.get('severity', 'N/A')
                if severity and severity != 'N/A':
                    html.append(f' <span style="color: #d73027; font-weight: bold; font-size: 0.85em;">[{severity}]</span>')

                html.append('<br>')

                # Show all affected versions as clickable links on second line
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">→ {", ".join(version_links)}</span>')
                html.append('</li>')

            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No new issues</p>')

        # Group closed issues by description for better readability
        closed_groups = self.group_issues_by_description(closed_issues, include_severity=True)
        html.append(f'<h3 style="color:#388e3c">✅ Closed Issues (Last 24h): {len(closed_groups)}</h3>')
        if closed_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in closed_groups.items():
                # Issue header with description and assignee in one line
                assignees_list = ", ".join(sorted(group_data['assignees'])) if group_data['assignees'] else "Unassigned"

                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #27ae60;">{group_data["cve_id"]}</strong>: {group_data["description"]} ({assignees_list})')
                else:
                    html.append(f'<li>{group_data["description"]} ({assignees_list})')

                # Show severity only if NOT N/A
                severity = group_data.get('severity', 'N/A')
                if severity and severity != 'N/A':
                    html.append(f' <span style="color: #d73027; font-weight: bold; font-size: 0.85em;">[{severity}]</span>')

                html.append('<br>')

                # Show all affected versions as clickable links on second line
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">→ {", ".join(version_links)}</span>')
                html.append('</li>')

            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No closed issues</p>')

        # Weekend Catch-Up (only on Mondays)
        if datetime.now().weekday() == 0:  # Monday
            weekend_new = self.get_weekend_new_issues(team_value)
            weekend_closed = self.get_weekend_closed_issues(team_value)

            html.append('<div style="background-color: #fffbf0; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0;">')
            html.append('<h4 style="color: #e67e22; margin-top: 0;">📅 Weekend Activity (Fri-Sun)</h4>')

            if weekend_new or weekend_closed:
                if weekend_new:
                    weekend_new_groups = self.group_issues_by_description(weekend_new, include_severity=True)
                    html.append(f'<p style="margin: 10px 0; color: #2166ac;"><strong>📌 New Issues: {len(weekend_new_groups)}</strong></p>')
                    html.append('<ul style="margin-left: 20px; margin-top: 5px;">')
                    for group_key, group_data in weekend_new_groups.items():
                        # Issue header with assignee
                        assignees_list = ", ".join(sorted(group_data['assignees'])) if group_data['assignees'] else "Unassigned"

                        if group_data["is_cve"]:
                            html.append(f'<li><strong style="color: #e74c3c;">{group_data["cve_id"]}</strong>: {group_data["description"]} ({assignees_list})')
                        else:
                            html.append(f'<li>{group_data["description"]} ({assignees_list})')

                        # Show severity only if NOT N/A
                        severity = group_data.get('severity', 'N/A')
                        if severity and severity != 'N/A':
                            html.append(f' <span style="color: #d73027; font-weight: bold; font-size: 0.85em;">[{severity}]</span>')

                        html.append('<br>')

                        # Show versions as links
                        version_links = []
                        for issue_data in group_data["issues"]:
                            issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                            display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                            version_links.append(
                                f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                            )
                        html.append(f'<span style="color: #666; font-size: 0.85em;">→ {", ".join(version_links)}</span></li>')

                    html.append('</ul>')

                if weekend_closed:
                    weekend_closed_groups = self.group_issues_by_description(weekend_closed, include_severity=True)
                    html.append(f'<p style="margin: 10px 0; color: #27ae60;"><strong>✅ Closed Issues: {len(weekend_closed_groups)}</strong></p>')
                    html.append('<ul style="margin-left: 20px; margin-top: 5px;">')
                    for group_key, group_data in weekend_closed_groups.items():
                        # Issue header with assignee
                        assignees_list = ", ".join(sorted(group_data['assignees'])) if group_data['assignees'] else "Unassigned"

                        if group_data["is_cve"]:
                            html.append(f'<li><strong>{group_data["cve_id"]}</strong>: {group_data["description"]} ({assignees_list})')
                        else:
                            html.append(f'<li>{group_data["description"]} ({assignees_list})')

                        # Show severity only if NOT N/A
                        severity = group_data.get('severity', 'N/A')
                        if severity and severity != 'N/A':
                            html.append(f' <span style="color: #d73027; font-weight: bold; font-size: 0.85em;">[{severity}]</span>')

                        html.append('<br>')

                        # Show versions as links
                        version_links = []
                        for issue_data in group_data["issues"]:
                            issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                            display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                            version_links.append(
                                f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                            )
                        html.append(f'<span style="color: #666; font-size: 0.85em;">→ {", ".join(version_links)}</span></li>')

                    html.append('</ul>')
            else:
                html.append('<p style="margin: 10px 0; color: #666;">No activity over the weekend</p>')

            html.append('</div>')

        # Section 2: CVE Issues (TABLE FORMAT)
        cve_issues = self.get_cve_issues(team_value)
        cve_groups = self.group_cves(cve_issues)
        html.append(f'<h3 style="color:#c62828">🔒 Active CVEs: {len(cve_groups)}</h3>')
        if cve_groups:
            html.append(self.generate_table_format(cve_groups, section_type="cve"))
            if len(cve_groups) > 15:
                html.append(f'<p style="margin-left: 20px; color: #999; font-style: italic;">... and {len(cve_groups) - 15} more CVEs not shown</p>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No active CVEs</p>')

        # Section 3: Prelim Testing Requested (TABLE FORMAT)
        prelim_testing = self.get_prelim_testing_requested(team_value)
        prelim_groups = self.group_issues_by_description(prelim_testing)
        html.append(f'<h3 style="color:#7b1fa2">🧪 Prelim Testing Requested: {len(prelim_groups)}</h3>')
        if prelim_groups:
            html.append(self.generate_table_format(prelim_groups, section_type="prelim"))
            if len(prelim_groups) > 15:
                html.append(f'<p style="margin-left: 20px; color: #999; font-style: italic;">... and {len(prelim_groups) - 15} more items not shown</p>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No prelim testing requested</p>')

        # Section 4: Integration Testing (TABLE FORMAT)
        integration_testing = self.get_integration_testing(team_value)
        integration_groups = self.group_issues_by_description(integration_testing)
        html.append(f'<h3 style="color:#00897b">🔬 Integration Testing: {len(integration_groups)}</h3>')
        if integration_groups:
            html.append(self.generate_table_format(integration_groups, section_type="integration"))
            if len(integration_groups) > 15:
                html.append(f'<p style="margin-left: 20px; color: #999; font-style: italic;">... and {len(integration_groups) - 15} more items not shown</p>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No integration testing issues</p>')

        # Section 4.5: Waiting on MR Merge (TABLE FORMAT)
        waiting_mr = self.get_waiting_on_mr_merge(team_value)
        waiting_mr_groups = self.group_issues_by_description(waiting_mr)
        html.append(f'<h3 style="color:#f57c00">⏳ Waiting on MR Merge: {len(waiting_mr_groups)}</h3>')
        if waiting_mr_groups:
            html.append(self.generate_table_format(waiting_mr_groups, section_type="waiting"))
            if len(waiting_mr_groups) > 15:
                html.append(f'<p style="margin-left: 20px; color: #999; font-style: italic;">... and {len(waiting_mr_groups) - 15} more items not shown</p>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No issues waiting on MR merge</p>')

        # Section 5: Customer Escalations (TABLE FORMAT)
        escalations = self.get_customer_escalations(team_value)
        html.append(f'<h3 style="color:#d73027">🚨 Customer Escalations: {len(escalations)}</h3>')
        if escalations:
            s = "padding:6px;border-bottom:"
            table_html = f"""<table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:0.9em"><thead><tr style="background-color:#f0f0f0"><th style="{s}2px solid #ddd;text-align:left">Issue</th><th style="{s}2px solid #ddd;text-align:left">Summary</th><th style="{s}2px solid #ddd;text-align:center">Priority</th><th style="{s}2px solid #ddd;text-align:left">Assignee</th><th style="{s}2px solid #ddd;text-align:left">Last Updated</th></tr></thead><tbody>"""

            for idx, issue in enumerate(escalations[:10]):
                key = issue["key"]
                summary = issue["fields"]["summary"]
                issue_url = f"{self.jira.url}/browse/{key}"

                if len(summary) > 100:
                    summary = summary[:97] + "..."

                priority = issue["fields"].get("priority", {}).get("name", "N/A") if issue["fields"].get("priority") else "N/A"
                assignee = issue["fields"].get("assignee", {}).get("displayName", "Unassigned") if issue["fields"].get("assignee") else "Unassigned"

                updated = issue["fields"].get("updated", "")
                if updated:
                    updated_dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                    updated_str = self._time_ago(updated_dt)
                else:
                    updated_str = "Unknown"

                # Priority color coding
                if priority == "Blocker":
                    priority_display = f'<span style="color:#d73027;font-weight:bold">{priority}</span>'
                elif priority == "Critical":
                    priority_display = f'<span style="color:#e67e22;font-weight:bold">{priority}</span>'
                elif priority == "Major":
                    priority_display = f'<span style="color:#f39c12">{priority}</span>'
                else:
                    priority_display = priority

                row_bg = "#fff" if idx % 2 == 0 else "#f9f9f9"
                c = "padding:6px;border-bottom:1px solid #eee"
                table_html += f"""<tr style="background-color:{row_bg}"><td style="{c}"><a href="{issue_url}" style="color:#3498db;text-decoration:none;font-weight:bold">{key}</a></td><td style="{c}">{summary}</td><td style="{c};text-align:center">{priority_display}</td><td style="{c}">{assignee}</td><td style="{c}">{updated_str}</td></tr>"""

            table_html += """</tbody></table>"""
            html.append(table_html)

            if len(escalations) > 10:
                html.append(f'<p style="margin-left:20px;color:#999;font-style:italic">... and {len(escalations) - 10} more escalations</p>')
        else:
            html.append('<p style="margin-left:20px;color:#666">No customer escalations</p>')

        # Section 5.5: Customer Bugs in NEW Status (TABLE FORMAT)
        customer_bugs_new = self.get_customer_bugs_new(team_value)
        html.append(f'<h3 style="color:#e74c3c">🆕 Customer Bugs in NEW Status (Needs Triage): {len(customer_bugs_new)}</h3>')
        if customer_bugs_new:
            # Generate table
            s = "padding:6px;border-bottom:"
            table_html = f"""<table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:0.9em"><thead><tr style="background-color:#f0f0f0"><th style="{s}2px solid #ddd;text-align:left">Issue</th><th style="{s}2px solid #ddd;text-align:left">Summary</th><th style="{s}2px solid #ddd;text-align:center">Source</th><th style="{s}2px solid #ddd;text-align:center">Severity</th><th style="{s}2px solid #ddd;text-align:left">Created</th><th style="{s}2px solid #ddd;text-align:left">Assignee</th></tr></thead><tbody>"""

            for idx, issue in enumerate(customer_bugs_new[:15]):
                key = issue["key"]
                summary = issue["fields"]["summary"]
                issue_url = f"{self.jira.url}/browse/{key}"

                # Truncate summary if too long
                if len(summary) > 100:
                    summary = summary[:97] + "..."

                # Extract reporter info
                reporter = issue["fields"].get("reporter", {})
                reporter_name = reporter.get("displayName", "Unknown") if reporter else "Unknown"
                is_bugproxy = reporter_name == "bugproxy bugproxy"

                # Check for SFDC cases
                sfdc_cases = issue["fields"].get(self.custom_fields["sfdc_cases"])
                has_sfdc = sfdc_cases is not None and sfdc_cases != ""

                # Get severity
                severity_field = issue["fields"].get(self.custom_fields["severity"])
                severity = severity_field.get("value", "N/A") if severity_field else "N/A"

                # Get created date
                created = issue["fields"].get("created", "")
                if created:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    created_str = created_dt.strftime("%b %d")
                    # Calculate age
                    age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                else:
                    created_str = "Unknown"
                    age_days = 0

                # Get assignee
                assignee = issue["fields"].get("assignee")
                assignee_name = assignee.get("displayName") if assignee else "Unassigned"

                # Build source badges
                source_badges = []
                if is_bugproxy:
                    source_badges.append('<span style="background-color:#3498db;color:white;padding:2px 4px;border-radius:2px;font-size:0.75em;font-weight:bold">IBM</span>')
                if has_sfdc:
                    source_badges.append('<span style="background-color:#e67e22;color:white;padding:2px 4px;border-radius:2px;font-size:0.75em;font-weight:bold">SFDC</span>')
                source_display = " ".join(source_badges) if source_badges else "-"

                # Severity display with color
                if severity == "Critical":
                    severity_display = f'<span style="color:#d73027;font-weight:bold">{severity}</span>'
                elif severity == "Important":
                    severity_display = f'<span style="color:#e67e22;font-weight:bold">{severity}</span>'
                elif severity == "Moderate":
                    severity_display = f'<span style="color:#f39c12">{severity}</span>'
                else:
                    severity_display = "-"

                # Age color coding
                if age_days > 60:
                    age_color = "#d73027"  # Red for old bugs
                elif age_days > 30:
                    age_color = "#e67e22"  # Orange for medium age
                else:
                    age_color = "#666"

                row_bg = "#fff" if idx % 2 == 0 else "#f9f9f9"
                c = "padding:6px;border-bottom:1px solid #eee"
                table_html += f"""<tr style="background-color:{row_bg}"><td style="{c}"><a href="{issue_url}" style="color:#3498db;text-decoration:none;font-weight:bold">{key}</a></td><td style="{c}">{summary}</td><td style="{c};text-align:center">{source_display}</td><td style="{c};text-align:center">{severity_display}</td><td style="{c};color:{age_color}">{created_str} ({age_days}d)</td><td style="{c}">{assignee_name}</td></tr>"""

            table_html += """</tbody></table>"""
            html.append(table_html)

            if len(customer_bugs_new) > 15:
                html.append(f'<p style="margin-left:20px;color:#999;font-style:italic">... and {len(customer_bugs_new) - 15} more untriaged customer bugs</p>')
        else:
            html.append('<p style="margin-left:20px;color:#28a745">✅ No untriaged customer bugs in NEW status</p>')

        # Section 6: Key Progress (TABLE FORMAT)
        progress = self.get_key_progress(team_value)
        progress_groups = self.group_issues_by_description(progress)
        html.append(f'<h3 style="color:#1976d2">📈 Key Progress: {len(progress_groups)}</h3>')
        if progress_groups:
            html.append(self.generate_table_format(progress_groups, section_type="progress"))
            if len(progress_groups) > 15:
                html.append(f'<p style="margin-left: 20px; color: #999; font-style: italic;">... and {len(progress_groups) - 15} more items not shown</p>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No key progress items</p>')

        # Section 7: Tasks (TABLE FORMAT)
        tasks = self.get_tasks(team_value)
        task_groups = self.group_issues_by_description(tasks)
        html.append(f'<h3 style="color:#616161">📋 Tasks (Updated Last 24h): {len(task_groups)}</h3>')
        if task_groups:
            html.append(self.generate_table_format(task_groups, section_type="tasks"))
            if len(task_groups) > 20:
                html.append(f'<p style="margin-left: 20px; color: #999; font-style: italic;">... and {len(task_groups) - 20} more task groups not shown</p>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No active tasks</p>')

        html.append('</div>')
        return '\n'.join(html)

    def generate_report(self):
        """Generate complete HTML report for all teams"""
        today = datetime.now().strftime("%B %d, %Y")

        html = [f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{{font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:900px;margin:0 auto;padding:20px}}h1{{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}}a{{color:#3498db;text-decoration:none}}a:hover{{text-decoration:underline}}</style></head><body><p style="color:#666;font-size:0.95em">Dashboard: <a href="https://redhat.atlassian.net/jira/dashboards/25063">FS Team Dashboard</a></p>"""]

        # Generate section for each team
        for team_name, team_value in self.config["teams"].items():
            try:
                html.append(self.generate_team_section(team_name, team_value))
            except Exception as e:
                html.append(f"""
<div style="margin-bottom: 30px; border: 1px solid #f00; padding: 20px; border-radius: 5px; background-color: #fee;">
<h2 style="color: #d73027;">⚠️ {team_name} - Error</h2>
<p>Failed to fetch data: {str(e)}</p>
</div>
""")

        html.append("""<hr style="margin-top:30px;border:none;border-top:1px solid #ddd"><p style="color:#333;font-size:0.95em;margin-top:20px">Regards,<br>Anand Reddy</p><p style="color:#999;font-size:0.85em;text-align:center;margin-top:20px">Generated by Daily PO Report System</p></body></html>""")

        return '\n'.join(html)

    def was_sent_today(self):
        """Check if report was already sent today"""
        last_sent_file = self.script_dir / self.LAST_SENT_FILE
        if not last_sent_file.exists():
            return False

        try:
            with open(last_sent_file, 'r') as f:
                last_sent = f.read().strip()
            today = datetime.now().strftime("%Y-%m-%d")
            return last_sent == today
        except Exception:
            return False

    def mark_as_sent_today(self):
        """Record that report was sent today"""
        last_sent_file = self.script_dir / self.LAST_SENT_FILE
        today = datetime.now().strftime("%Y-%m-%d")
        with open(last_sent_file, 'w') as f:
            f.write(today)

    def send_email(self, html_content, dry_run=False, force=False):
        """Send email via SMTP"""
        # Check if already sent today (unless forced or dry-run)
        if not dry_run and not force and self.was_sent_today():
            print(f"ℹ Report already sent today. Skipping.")
            return

        today = datetime.now().strftime("%B %d, %Y")
        is_monday = datetime.now().weekday() == 0
        subject = f"FS Teams Daily Digest - {today}" + (" (with Weekend Activity)" if is_monday else "")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.config.get("sender_email", self.config["recipient"])
        msg['To'] = self.config["recipient"]

        # Attach HTML content
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)

        if dry_run:
            print("=" * 80)
            print("DRY RUN MODE - Email not sent")
            print("=" * 80)
            print(f"From: {msg['From']}")
            print(f"To: {msg['To']}")
            print(f"Subject: {msg['Subject']}")
            print("=" * 80)
            print(html_content)
            print("=" * 80)
            return

        # Send email
        smtp_method = self.config.get("smtp_method", "gmail")

        if smtp_method == "gmail":
            # Read Gmail app password from .env file
            from dotenv import load_dotenv
            load_dotenv()
            gmail_password = os.getenv("GMAIL_APP_PASSWORD")

            if not gmail_password:
                print("ERROR: GMAIL_APP_PASSWORD not found in .env file")
                print("Please create a .env file with:")
                print("GMAIL_APP_PASSWORD=your_gmail_app_specific_password")
                sys.exit(1)

            smtp_server = self.config["smtp_server"]
            smtp_port = self.config["smtp_port"]

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(self.config["sender_email"], gmail_password)
                server.send_message(msg)

        else:  # redhat SMTP
            # Red Hat SMTP - try without auth first (internal relay)
            smtp_server = self.config["smtp_server"]
            smtp_port = self.config["smtp_port"]

            try:
                # Try plain SMTP (port 25, no auth, no TLS)
                with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                    server.send_message(msg)
            except Exception as e:
                # If that fails, try with STARTTLS on port 587
                print(f"Port {smtp_port} failed, trying port 587 with STARTTLS...")
                with smtplib.SMTP(smtp_server, 587, timeout=10) as server:
                    server.starttls()
                    server.send_message(msg)

        # Mark as sent
        self.mark_as_sent_today()
        print(f"✓ Email sent successfully to {self.config['recipient']}")


def main():
    parser = argparse.ArgumentParser(description="Generate and send daily PO report")
    parser.add_argument("--dry-run", action="store_true", help="Generate report but don't send email")
    parser.add_argument("--force", action="store_true", help="Send even if already sent today")
    parser.add_argument("--check-only", action="store_true", help="Only check if report needed, don't send")
    parser.add_argument("--config", default="email_config.json", help="Path to config file")
    args = parser.parse_args()

    try:
        generator = POReportGenerator(args.config)

        # Check-only mode: just report status
        if args.check_only:
            if generator.was_sent_today():
                print("✓ Report already sent today")
                sys.exit(0)
            else:
                print("⚠ Report NOT sent today - needs to be sent")
                sys.exit(1)

        # Generate and send
        html_content = generator.generate_report()
        generator.send_email(html_content, dry_run=args.dry_run, force=args.force)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
