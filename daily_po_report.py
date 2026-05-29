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

        fields = ["summary", "status", "priority", "assignee", "created", "updated", "issuetype", self.custom_fields["severity"], "labels"]
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
                "assignee": issue["fields"].get("assignee", {}).get("displayName", "Unassigned"),
                "priority": issue["fields"].get("priority", {}).get("name", "Undefined") if issue["fields"].get("priority") else "Undefined"
            })

            if issue["fields"].get("assignee"):
                grouped[group_key]["assignees"].add(issue["fields"]["assignee"]["displayName"])

        return grouped

    def group_cves(self, issues):
        """Group CVE issues by CVE ID - wrapper for backward compatibility"""
        return self.group_issues_by_description(issues, include_severity=True)

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
        html = [f"""
<div style="margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 5px; background-color: #f9f9f9;">
<h2 style="color: #d73027; border-bottom: 2px solid #d73027; padding-bottom: 10px;">📊 {team_name}</h2>
"""]

        # Section 1: New & Closed Issues
        new_issues = self.get_new_issues(team_value)
        closed_issues = self.get_closed_issues(team_value)

        # Group new issues by description for better readability
        new_groups = self.group_issues_by_description(new_issues, include_severity=True)
        html.append(f'<h3 style="color: #2166ac;">📌 New Issues (Last 24h): {len(new_groups)}</h3>')
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
        html.append(f'<h3 style="color: #2166ac;">✅ Closed Issues (Last 24h): {len(closed_groups)}</h3>')
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

        # Section 2: CVE Issues (grouped by CVE ID)
        cve_issues = self.get_cve_issues(team_value)
        cve_groups = self.group_cves(cve_issues)
        html.append(f'<h3 style="color: #d73027;">🔒 Active CVEs: {len(cve_groups)}</h3>')
        if cve_groups:
            html.append('<ul style="margin-left: 20px;">')
            for cve_id, cve_data in list(cve_groups.items())[:15]:  # Show up to 15 CVEs
                # CVE header with description
                if cve_id.startswith("CVE-"):
                    html.append(f'<li><strong style="color: #d73027;">{cve_id}</strong>: {cve_data["description"]}<br>')
                else:
                    # Non-CVE security issue
                    html.append(f'<li>{cve_data["description"]}<br>')

                # Show severity and assignees
                details = [f"Severity: {cve_data['severity']}"]
                if cve_data['assignees']:
                    assignees_list = ", ".join(sorted(cve_data['assignees']))
                    details.append(f"Assignee(s): {assignees_list}")
                html.append(f'<span style="color: #666; font-size: 0.9em;">{" | ".join(details)}</span><br>')

                # Show all affected versions as clickable links
                version_links = []
                for issue_data in cve_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    version_info = f"{issue_data['version']}" if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{version_info}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">Affects: {", ".join(version_links)}</span>')
                html.append('</li>')

            if len(cve_groups) > 15:
                html.append(f'<li><em>... and {len(cve_groups) - 15} more CVEs</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No active CVEs</p>')

        # Section 3: Prelim Testing Requested (grouped)
        prelim_testing = self.get_prelim_testing_requested(team_value)
        prelim_groups = self.group_issues_by_description(prelim_testing)
        html.append(f'<h3 style="color: #8e44ad;">🧪 Prelim Testing Requested: {len(prelim_groups)}</h3>')
        if prelim_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in list(prelim_groups.items())[:15]:
                # Issue header
                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #8e44ad;">{group_data["cve_id"]}</strong>: {group_data["description"]}<br>')
                else:
                    html.append(f'<li>{group_data["description"]}<br>')

                # Show assignees
                if group_data['assignees']:
                    assignees_list = ", ".join(sorted(group_data['assignees']))
                    html.append(f'<span style="color: #666; font-size: 0.9em;">Assignee(s): {assignees_list}</span><br>')

                # Show all versions/instances as clickable links
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">Affects: {", ".join(version_links)}</span>')
                html.append('</li>')

            if len(prelim_groups) > 15:
                html.append(f'<li><em>... and {len(prelim_groups) - 15} more items</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No prelim testing requested</p>')

        # Section 4: Integration Testing (grouped)
        integration_testing = self.get_integration_testing(team_value)
        integration_groups = self.group_issues_by_description(integration_testing)
        html.append(f'<h3 style="color: #16a085;">🔬 Integration Testing: {len(integration_groups)}</h3>')
        if integration_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in list(integration_groups.items())[:15]:
                # Issue header
                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #16a085;">{group_data["cve_id"]}</strong>: {group_data["description"]}<br>')
                else:
                    html.append(f'<li>{group_data["description"]}<br>')

                # Show assignees
                if group_data['assignees']:
                    assignees_list = ", ".join(sorted(group_data['assignees']))
                    html.append(f'<span style="color: #666; font-size: 0.9em;">Assignee(s): {assignees_list}</span><br>')

                # Show all versions/instances as clickable links
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">Affects: {", ".join(version_links)}</span>')
                html.append('</li>')

            if len(integration_groups) > 15:
                html.append(f'<li><em>... and {len(integration_groups) - 15} more items</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No integration testing issues</p>')

        # Section 4.5: Waiting on MR Merge (grouped)
        waiting_mr = self.get_waiting_on_mr_merge(team_value)
        waiting_mr_groups = self.group_issues_by_description(waiting_mr)
        html.append(f'<h3 style="color: #f39c12;">⏳ Waiting on MR Merge: {len(waiting_mr_groups)}</h3>')
        if waiting_mr_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in list(waiting_mr_groups.items())[:15]:
                # Issue header
                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #f39c12;">{group_data["cve_id"]}</strong>: {group_data["description"]}<br>')
                else:
                    html.append(f'<li>{group_data["description"]}<br>')

                # Show assignees
                if group_data['assignees']:
                    assignees_list = ", ".join(sorted(group_data['assignees']))
                    html.append(f'<span style="color: #666; font-size: 0.9em;">Assignee(s): {assignees_list}</span><br>')

                # Show all versions/instances as clickable links
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">Waiting: {", ".join(version_links)}</span>')
                html.append('</li>')

            if len(waiting_mr_groups) > 15:
                html.append(f'<li><em>... and {len(waiting_mr_groups) - 15} more items</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No issues waiting on MR merge</p>')

        # Section 5: Customer Escalations
        escalations = self.get_customer_escalations(team_value)
        html.append(f'<h3 style="color: #d73027;">🚨 Customer Escalations: {len(escalations)}</h3>')
        if escalations:
            html.append('<ul style="margin-left: 20px;">')
            for issue in escalations[:10]:
                html.append(f'<li>{self.format_issue_line(issue, include_fields=["priority", "sfdc_cases", "assignee", "updated"])}</li>')
            if len(escalations) > 10:
                html.append(f'<li><em>... and {len(escalations) - 10} more</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No customer escalations</p>')

        # Section 6: Key Progress (grouped)
        progress = self.get_key_progress(team_value)
        progress_groups = self.group_issues_by_description(progress)
        html.append(f'<h3 style="color: #2166ac;">📈 Key Progress: {len(progress_groups)}</h3>')
        if progress_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in list(progress_groups.items())[:15]:
                # Issue header
                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #2166ac;">{group_data["cve_id"]}</strong>: {group_data["description"]}<br>')
                else:
                    html.append(f'<li>{group_data["description"]}<br>')

                # Show assignees
                if group_data['assignees']:
                    assignees_list = ", ".join(sorted(group_data['assignees']))
                    html.append(f'<span style="color: #666; font-size: 0.9em;">Assignee(s): {assignees_list}</span><br>')

                # Show all versions/instances as clickable links with status
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    # Show status in the tooltip
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">Progress: {", ".join(version_links)}</span>')
                html.append('</li>')

            if len(progress_groups) > 15:
                html.append(f'<li><em>... and {len(progress_groups) - 15} more items</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No key progress items</p>')

        # Section 7: Tasks (updated in last 24h, grouped)
        tasks = self.get_tasks(team_value)
        task_groups = self.group_issues_by_description(tasks)
        html.append(f'<h3 style="color: #6c757d;">📋 Tasks (Updated Last 24h): {len(task_groups)}</h3>')
        if task_groups:
            html.append('<ul style="margin-left: 20px;">')
            for group_key, group_data in list(task_groups.items())[:20]:  # Show more tasks
                # Task header
                if group_data["is_cve"]:
                    html.append(f'<li><strong style="color: #6c757d;">{group_data["cve_id"]}</strong>: {group_data["description"]}<br>')
                else:
                    html.append(f'<li>{group_data["description"]}<br>')

                # Show assignees
                if group_data['assignees']:
                    assignees_list = ", ".join(sorted(group_data['assignees']))
                    html.append(f'<span style="color: #666; font-size: 0.9em;">Assignee(s): {assignees_list}</span><br>')

                # Show all versions/instances as clickable links
                version_links = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_links.append(
                        f'<a href="{issue_url}" style="color: #3498db; text-decoration: none;" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                    )
                html.append(f'<span style="color: #666; font-size: 0.85em;">Tasks: {", ".join(version_links)}</span>')
                html.append('</li>')

            if len(task_groups) > 20:
                html.append(f'<li><em>... and {len(task_groups) - 20} more task groups</em></li>')
            html.append('</ul>')
        else:
            html.append('<p style="margin-left: 20px; color: #666;">No active tasks</p>')

        html.append('</div>')
        return '\n'.join(html)

    def generate_report(self):
        """Generate complete HTML report for all teams"""
        today = datetime.now().strftime("%B %d, %Y")

        html = [f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        a {{ color: #3498db; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
<p style="color: #666; font-size: 0.95em;">
Dashboard: <a href="https://redhat.atlassian.net/jira/dashboards/25063">FS Team Dashboard</a>
</p>
"""]

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

        html.append("""
<hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
<p style="color: #333; font-size: 0.95em; margin-top: 20px;">
Regards,<br>
Anand Reddy
</p>
<p style="color: #999; font-size: 0.85em; text-align: center; margin-top: 20px;">
Generated by Daily PO Report System
</p>
</body>
</html>
""")

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
