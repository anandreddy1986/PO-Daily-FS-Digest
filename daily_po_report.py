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

    def search_issues(self, jql, fields=None, max_results=500):
        """Search Jira issues using JQL with automatic cursor-based pagination"""
        endpoint = f"{self.url}/rest/api/3/search/jql"
        page_size = min(max_results, 100)
        fields_str = ",".join(fields) if fields else "summary,status,priority,assignee,created,updated,fixVersions"

        all_issues = []
        next_page_token = None

        try:
            while len(all_issues) < max_results:
                params = {
                    "jql": jql,
                    "maxResults": min(page_size, max_results - len(all_issues)),
                    "fields": fields_str
                }
                if next_page_token:
                    params["nextPageToken"] = next_page_token

                response = requests.get(endpoint, headers=self.headers, auth=self.auth, params=params)
                response.raise_for_status()
                result = response.json()
                if result is None:
                    break

                page_issues = result.get("issues", [])
                if not page_issues:
                    break

                all_issues.extend(page_issues)
                next_page_token = result.get("nextPageToken")

                if not next_page_token or len(page_issues) < page_size:
                    break

            return {"issues": all_issues, "total": len(all_issues)}
        except Exception as e:
            print(f"ERROR in search_issues: {str(e)}")
            print(f"JQL: {jql}")
            return {"issues": all_issues if all_issues else [], "total": len(all_issues)}


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
        """Get issues created in last 24 hours for a team (Bug, Story only - CVEs shown in CVE section)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND type in (Bug, Story) AND summary !~ "CVE-" AND created >= -24h'
        result = self.jira.search_issues(jql, max_results=500)
        return result.get("issues", [])

    def get_closed_issues(self, team_value):
        """Get issues closed in last 24 hours for a team (Bug, Story only - CVEs shown in CVE section)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND type in (Bug, Story) AND summary !~ "CVE-" AND status changed to (Closed, Done, Resolved) DURING (-24h, now())'
        result = self.jira.search_issues(jql, max_results=500)
        return result.get("issues", [])

    def get_weekend_new_issues(self, team_value):
        """Get issues created over the weekend (Friday-Sunday, i.e., 24h-72h ago)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND type in (Bug, Story) AND summary !~ "CVE-" AND created >= -72h AND created < -24h'
        result = self.jira.search_issues(jql, max_results=500)
        return result.get("issues", [])

    def get_weekend_closed_issues(self, team_value):
        """Get issues closed over the weekend (Friday-Sunday, i.e., 24h-72h ago)"""
        jql = f'project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND type in (Bug, Story) AND summary !~ "CVE-" AND status changed to (Closed, Done, Resolved) DURING (-72h, -24h)'
        result = self.jira.search_issues(jql, max_results=500)
        return result.get("issues", [])

    def get_cve_issues(self, team_value):
        """Get active CVE/security issues for a team

        Uses two queries to ensure complete coverage:
        1. All Vulnerability/Weakness type issues (catches embargoed items)
        2. Bug/Story issues with CVE in summary (catches CVE-tracked bugs)
        """
        import re

        fields = ["summary", "status", "priority", "assignee", "created", "updated", "issuetype", self.custom_fields["severity"], self.custom_fields["cvss_score"], "labels", "duedate", "fixVersions"]

        # Query 1: All Vulnerability/Weakness type issues (includes embargoed CVEs)
        jql_vuln = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Vulnerability, Weakness) AND
                 status not in (Closed, Done, Resolved, "Release Pending", Integration)'''
        result_vuln = self.jira.search_issues(jql_vuln, fields=fields, max_results=500)

        # Query 2: Bug/Story issues that have CVE in summary (CVE-tracked bugs)
        jql_bugs = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Story) AND
                 summary ~ "CVE-" AND
                 status not in (Closed, Done, Resolved, "Release Pending", Integration)'''
        result_bugs = self.jira.search_issues(jql_bugs, fields=fields, max_results=500)

        # Combine results, dedup by issue key
        seen_keys = set()
        cve_issues = []

        for issue in result_vuln.get("issues", []):
            if issue["key"] not in seen_keys:
                seen_keys.add(issue["key"])
                cve_issues.append(issue)

        for issue in result_bugs.get("issues", []):
            if issue["key"] not in seen_keys:
                seen_keys.add(issue["key"])
                cve_issues.append(issue)

        return cve_issues

    def get_prelim_testing_requested(self, team_value):
        """Get issues with Preliminary Testing criteria"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 ("Preliminary Testing" = Requested OR status = "In Progress" AND ("Preliminary Testing" = Requested OR issuetype = Task AND labels = KWF:Task)) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["summary", "status", "priority", "assignee", "updated", "labels", "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        return result.get("issues", [])

    def get_integration_testing(self, team_value):
        """Get issues with Status = Integration and Fixed in Build is not empty"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 status = Integration AND "Fixed in Build" is not EMPTY'''

        fields = ["summary", "status", "priority", "assignee", "updated", "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        return result.get("issues", [])

    def get_customer_escalations(self, team_value):
        """Get customer escalations (Escalation🔥/escalated label, Customer Escalated, or Priority List linked)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Story) AND summary !~ "CVE-" AND
                 (labels = "Escalation🔥" OR labels = "escalated" OR "Customer Impact" = "Customer Escalated" OR issueLink = RHELPRIO) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["summary", "status", "priority", "assignee", "updated", self.custom_fields["sfdc_cases_counter"], self.custom_fields["customer_impact"], "labels", "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        return result.get("issues", [])

    def get_customer_bugs_new(self, team_value):
        """Get customer-related bugs in NEW status (SFDC cases, Customer Impact, or bugproxy reported)

        Note: SFDC Cases Counter field is encrypted, so JQL cannot query it directly.
        We fetch all NEW bugs and filter in Python based on field presence.
        """
        # Get all NEW bugs for the team (CVEs shown separately in CVE section)
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Story) AND summary !~ "CVE-" AND
                 status = "New"'''

        fields = ["summary", "status", "priority", "assignee", "created", "updated", "reporter",
                  self.custom_fields["sfdc_cases_counter"],
                  self.custom_fields["sfdc_cases_links"],
                  self.custom_fields["sfdc_cases_open"],
                  self.custom_fields["customer_impact"],
                  self.custom_fields["severity"],
                  "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        # Filter for customer bugs in Python
        customer_bugs = []
        for issue in result.get("issues", []):
            is_customer_bug = False

            # Check 1: Reporter is bugproxy (IBM customer reports)
            reporter = issue["fields"].get("reporter", {})
            if reporter and reporter.get("displayName") == "bugproxy bugproxy":
                is_customer_bug = True

            # Check 2: Customer Impact field is set (but exclude "Customer Facing" - that's just a feature flag, not a customer bug)
            customer_impact = issue["fields"].get(self.custom_fields["customer_impact"])
            if customer_impact:
                # Get the actual value - can be dict with "value" key or direct value
                impact_value = customer_impact.get("value") if isinstance(customer_impact, dict) else customer_impact

                # Exclude if it's ONLY "Customer Facing"
                if isinstance(impact_value, list):
                    # Extract string values from list of dicts (e.g., [{'value': 'Customer Facing'}])
                    values = []
                    for item in impact_value:
                        if isinstance(item, dict) and "value" in item:
                            values.append(item["value"])
                        elif isinstance(item, str):
                            values.append(item)

                    # If it's a list with only "Customer Facing", skip it
                    if not (len(values) == 1 and values[0] == "Customer Facing"):
                        is_customer_bug = True
                elif impact_value and impact_value != "Customer Facing":
                    is_customer_bug = True

            # Check 3: SFDC Cases Counter has encrypted value (indicates customer case exists)
            # Note: Field can be either a string or {"value": "..."} dict depending on API endpoint
            sfdc_counter = issue["fields"].get(self.custom_fields["sfdc_cases_counter"])
            if sfdc_counter:
                if isinstance(sfdc_counter, str):  # Plain string format from search API
                    is_customer_bug = True
                elif isinstance(sfdc_counter, dict) and sfdc_counter.get("value"):  # Dict format from get issue API
                    is_customer_bug = True

            # Check 4: SFDC Cases Links has value
            sfdc_links = issue["fields"].get(self.custom_fields["sfdc_cases_links"])
            if sfdc_links:
                if isinstance(sfdc_links, str):
                    is_customer_bug = True
                elif isinstance(sfdc_links, dict) and sfdc_links.get("value"):
                    is_customer_bug = True

            # Check 5: SFDC Cases Open has value
            sfdc_open = issue["fields"].get(self.custom_fields["sfdc_cases_open"])
            if sfdc_open:
                if isinstance(sfdc_open, str):
                    is_customer_bug = True
                elif isinstance(sfdc_open, dict) and sfdc_open.get("value"):
                    is_customer_bug = True

            # Check 6: Reporter is not an FS team member (likely external/customer report)
            if not is_customer_bug:
                reporter_id = reporter.get("accountId") if reporter else None
                if reporter_id and reporter_id not in self._get_fs_team_member_ids():
                    is_customer_bug = True

            if is_customer_bug:
                customer_bugs.append(issue)

        return customer_bugs

    def get_customer_bugs_in_flight(self, team_value):
        """Get customer-related bugs in any active status, excluding CVEs and Closed (SFDC cases, Customer Impact, or bugproxy reported)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Story) AND
                 status not in (New, Closed, "Release Pending", "Integration")'''

        fields = ["summary", "status", "priority", "assignee", "created", "updated", "reporter",
                  self.custom_fields["sfdc_cases_counter"],
                  self.custom_fields["sfdc_cases_links"],
                  self.custom_fields["sfdc_cases_open"],
                  self.custom_fields["customer_impact"],
                  self.custom_fields["severity"],
                  "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        customer_bugs = []
        for issue in result.get("issues", []):
            is_customer_bug = False

            reporter = issue["fields"].get("reporter", {})
            if reporter and reporter.get("displayName") == "bugproxy bugproxy":
                is_customer_bug = True

            customer_impact = issue["fields"].get(self.custom_fields["customer_impact"])
            if customer_impact:
                impact_value = customer_impact.get("value") if isinstance(customer_impact, dict) else customer_impact
                if isinstance(impact_value, list):
                    values = []
                    for item in impact_value:
                        if isinstance(item, dict) and "value" in item:
                            values.append(item["value"])
                        elif isinstance(item, str):
                            values.append(item)
                    if not (len(values) == 1 and values[0] == "Customer Facing"):
                        is_customer_bug = True
                elif impact_value and impact_value != "Customer Facing":
                    is_customer_bug = True

            sfdc_counter = issue["fields"].get(self.custom_fields["sfdc_cases_counter"])
            if sfdc_counter:
                if isinstance(sfdc_counter, str):
                    is_customer_bug = True
                elif isinstance(sfdc_counter, dict) and sfdc_counter.get("value"):
                    is_customer_bug = True

            sfdc_links = issue["fields"].get(self.custom_fields["sfdc_cases_links"])
            if sfdc_links:
                if isinstance(sfdc_links, str):
                    is_customer_bug = True
                elif isinstance(sfdc_links, dict) and sfdc_links.get("value"):
                    is_customer_bug = True

            sfdc_open = issue["fields"].get(self.custom_fields["sfdc_cases_open"])
            if sfdc_open:
                if isinstance(sfdc_open, str):
                    is_customer_bug = True
                elif isinstance(sfdc_open, dict) and sfdc_open.get("value"):
                    is_customer_bug = True

            # Check 6: Reporter is not an FS team member (likely external/customer report)
            if not is_customer_bug:
                reporter_id = reporter.get("accountId") if reporter else None
                if reporter_id and reporter_id not in self._get_fs_team_member_ids():
                    is_customer_bug = True

            if is_customer_bug:
                customer_bugs.append(issue)

        return customer_bugs

    def get_waiting_on_mr_merge(self, team_value):
        """Get issues waiting on MR merge (Testable Builds exist but Preliminary Testing not started)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Vulnerability) AND
                 status = "In Progress" AND
                 "Testable Builds" is not EMPTY AND
                 "Preliminary Testing" is EMPTY'''

        fields = ["summary", "status", "priority", "assignee", "updated", self.custom_fields["testable_builds"], "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        return result.get("issues", [])

    def get_internal_bugs_awaiting_triage(self, team_value):
        """Get non-customer, non-CVE bugs in NEW status awaiting triage"""
        import re as _re

        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Story) AND summary !~ "CVE-" AND
                 status = "New" AND
                 created <= -24h'''

        fields = ["summary", "status", "priority", "assignee", "created", "updated", "reporter",
                  "issuetype", "labels",
                  self.custom_fields["sfdc_cases_counter"],
                  self.custom_fields["sfdc_cases_links"],
                  self.custom_fields["sfdc_cases_open"],
                  self.custom_fields["customer_impact"],
                  self.custom_fields["severity"],
                  "fixVersions"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        non_customer_bugs = []
        for issue in result.get("issues", []):
            # Exclude CVE/security issues (already shown in CVE section)
            is_cve = False
            if issue["fields"]["issuetype"]["name"] in ["Vulnerability", "Weakness"]:
                is_cve = True
            if _re.search(r'CVE-\d{4}-\d+', issue["fields"]["summary"], _re.IGNORECASE):
                is_cve = True
            labels = issue["fields"].get("labels", [])
            for label in labels:
                if _re.match(r'CVE-\d{4}-\d+', label, _re.IGNORECASE):
                    is_cve = True
                    break
            if is_cve:
                continue
            is_customer_bug = False

            reporter = issue["fields"].get("reporter", {})
            if reporter and reporter.get("displayName") == "bugproxy bugproxy":
                is_customer_bug = True

            customer_impact = issue["fields"].get(self.custom_fields["customer_impact"])
            if customer_impact:
                impact_value = customer_impact.get("value") if isinstance(customer_impact, dict) else customer_impact
                if isinstance(impact_value, list):
                    values = []
                    for item in impact_value:
                        if isinstance(item, dict) and "value" in item:
                            values.append(item["value"])
                        elif isinstance(item, str):
                            values.append(item)
                    if not (len(values) == 1 and values[0] == "Customer Facing"):
                        is_customer_bug = True
                elif impact_value and impact_value != "Customer Facing":
                    is_customer_bug = True

            sfdc_counter = issue["fields"].get(self.custom_fields["sfdc_cases_counter"])
            if sfdc_counter:
                if isinstance(sfdc_counter, str):
                    is_customer_bug = True
                elif isinstance(sfdc_counter, dict) and sfdc_counter.get("value"):
                    is_customer_bug = True

            sfdc_links = issue["fields"].get(self.custom_fields["sfdc_cases_links"])
            if sfdc_links:
                if isinstance(sfdc_links, str):
                    is_customer_bug = True
                elif isinstance(sfdc_links, dict) and sfdc_links.get("value"):
                    is_customer_bug = True

            sfdc_open = issue["fields"].get(self.custom_fields["sfdc_cases_open"])
            if sfdc_open:
                if isinstance(sfdc_open, str):
                    is_customer_bug = True
                elif isinstance(sfdc_open, dict) and sfdc_open.get("value"):
                    is_customer_bug = True

            # Also exclude if reporter is not an FS team member (likely external/customer-originated)
            if not is_customer_bug:
                reporter_id = reporter.get("accountId") if reporter else None
                if reporter_id and reporter_id not in self._get_fs_team_member_ids():
                    is_customer_bug = True

            if not is_customer_bug:
                non_customer_bugs.append(issue)

        return non_customer_bugs

    def get_key_progress(self, team_value):
        """Get recently updated high-priority items showing progress (Bug, Story only - CVEs shown in CVE section)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type in (Bug, Story) AND summary !~ "CVE-" AND
                 priority in (Blocker, Critical, Major) AND
                 updated >= -24h AND
                 status in ("In Progress", "In Review", "Testing", "QE Review") AND
                 status not in ("Release Pending")'''

        result = self.jira.search_issues(jql, max_results=500)
        return result.get("issues", [])

    def get_tasks(self, team_value):
        """Get Task type issues updated in last 24h for a team (excluding KWF automated tasks)"""
        jql = f'''project = {self.config["jira_project"]} AND AssignedTeam = {team_value} AND
                 type = Task AND
                 updated >= -24h AND
                 status not in (Closed, Done, Resolved, "Release Pending") AND
                 summary !~ "[KWF:"'''

        result = self.jira.search_issues(jql, max_results=500)
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

            # Extract version tag (e.g., [rhel-10.3]) from summary first
            version_match = re.search(r'\[(rhel-[\d.z]+)\]', summary)
            version = version_match.group(1) if version_match else ""

            # Fallback: try to get version from fixVersions field if not in summary
            if not version:
                fix_versions = issue["fields"].get("fixVersions", [])
                if fix_versions and len(fix_versions) > 0:
                    # Use first fix version
                    version = fix_versions[0].get("name", "")

            if cve_match:
                # CVE-based grouping
                cve_id = cve_match.group(1).upper()
                desc_match = re.search(r'CVE-\d{4}-\d+\s+(.+?)(?:\s+\[|$)', clean_summary, re.IGNORECASE)
                description = desc_match.group(1).strip() if desc_match else clean_summary
                group_key = cve_id
            else:
                # Non-CVE: group by description without version tag
                description = re.sub(r'\s*\[rhel-[\d.z]+\]', '', clean_summary).strip()
                group_key = f"DESC-{description[:200]}"

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

            # Extract CVSS score if available
            cvss_field = issue["fields"].get(self.custom_fields.get("cvss_score", ""), None)
            cvss_score = None
            if cvss_field:
                if isinstance(cvss_field, (int, float)):
                    cvss_score = cvss_field
                elif isinstance(cvss_field, dict):
                    cvss_val = cvss_field.get("value") or cvss_field.get("score")
                    if cvss_val:
                        try:
                            cvss_score = float(str(cvss_val).split()[0])
                        except (ValueError, TypeError):
                            pass
                elif isinstance(cvss_field, str):
                    try:
                        cvss_score = float(cvss_field.split()[0])
                    except (ValueError, TypeError):
                        pass

            grouped[group_key]["issues"].append({
                "key": issue["key"],
                "version": version,
                "status": issue["fields"]["status"]["name"],
                "assignee": issue["fields"]["assignee"]["displayName"] if issue["fields"].get("assignee") else "Unassigned",
                "priority": issue["fields"]["priority"]["name"] if issue["fields"].get("priority") else "Undefined",
                "duedate": issue["fields"].get("duedate"),
                "cvss_score": cvss_score
            })

            if issue["fields"].get("assignee"):
                assignee_name = issue["fields"]["assignee"]["displayName"]
                if not self._is_filtered_assignee(assignee_name):
                    grouped[group_key]["assignees"].add(assignee_name)

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

        # Reduced padding: 3px instead of 6px for compact tables
        th = "padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0"
        th_c = "padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0"

        if section_type == "cve":
            table_style = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="{th}">CVE</th><th style="{th}">Description</th><th style="{th_c}">Phase</th><th style="{th}">Assignee</th><th style="{th_c}">#</th><th style="{th}">Versions/Due/CVSS</th></tr></thead><tbody>"""
        elif section_type in ["new", "closed"]:
            table_style = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="{th}">Bug/CVE</th><th style="{th}">Description</th><th style="{th}">Assignee</th><th style="{th}">Versions</th></tr></thead><tbody>"""
        else:
            table_style = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="{th}">ID</th><th style="{th}">Description</th><th style="{th}">Assignee</th><th style="{th_c}">#</th><th style="{th}">Versions</th></tr></thead><tbody>"""

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
            for issue_data in group_data["issues"]:
                issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                version_links.append(
                    f'<a href="{issue_url}" style="color:#3498db;text-decoration:none" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                )

            versions_str = ", ".join(version_links)

            # CVE specific columns
            if section_type == "cve":
                cve_id = group_data.get("cve_id", "")

                # Get first issue key for CVE link
                first_issue_key = group_data['issues'][0]['key'] if group_data['issues'] else ""
                first_issue_url = f"{self.jira.url}/browse/{first_issue_key}" if first_issue_key else "#"

                # Build CVE ID display with link
                if cve_id:
                    cve_display = f'<a href="{first_issue_url}" style="color:#d73027;text-decoration:none;font-weight:bold">{cve_id}</a>'
                else:
                    cve_display = f'<a href="{first_issue_url}" style="color:#666;text-decoration:none;font-weight:bold">Non-CVE</a>'

                # Phase (status) display with color coding
                first_status = group_data['issues'][0]['status'] if group_data['issues'] else "New"
                phase_colors = {
                    "New": ("background:#dfe1e6;color:#44546f", "New"),
                    "In Progress": ("background:#deebff;color:#0747a6", "In Prog"),
                    "Planning": ("background:#eae6ff;color:#403294", "Plan"),
                    "Integration": ("background:#e3fcef;color:#006644", "Integr"),
                }
                phase_style, phase_text = phase_colors.get(first_status, ("background:#dfe1e6;color:#44546f", first_status[:6]))
                phase_display = f'<span style="{phase_style};padding:1px 5px;border-radius:3px;font-size:0.8em;font-weight:bold;white-space:nowrap">{phase_text}</span>'

                # Build combined Versions/Due/CVSS column
                version_due_parts = []
                for issue_data in group_data["issues"]:
                    issue_url = f"{self.jira.url}/browse/{issue_data['key']}"
                    display_text = issue_data['version'] if issue_data['version'] else issue_data['key']
                    version_link = f'<a href="{issue_url}" style="color:#3498db;text-decoration:none" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'

                    # Add due date and CVSS inline
                    due_cvss_parts = []
                    due_urgency = None  # "overdue", "soon", or None
                    if issue_data.get('duedate'):
                        try:
                            due_dt = datetime.strptime(issue_data['duedate'], "%Y-%m-%d")
                            due_str = f"{due_dt.month}/{due_dt.day}"
                            if due_dt < datetime.now():
                                due_str += "!"
                                due_urgency = "overdue"
                            elif due_dt <= datetime.now() + timedelta(days=14):
                                due_urgency = "soon"
                            due_cvss_parts.append(due_str)
                        except:
                            pass
                    if issue_data.get('cvss_score'):
                        due_cvss_parts.append(str(issue_data['cvss_score']))

                    if due_cvss_parts:
                        if due_urgency == "overdue":
                            version_due_parts.append(f'{version_link}<span style="color:#d73027;font-weight:bold">({", ".join(due_cvss_parts)})</span>')
                        elif due_urgency == "soon":
                            version_due_parts.append(f'{version_link}<span style="color:#d73027;font-weight:bold">({", ".join(due_cvss_parts)})</span>')
                        else:
                            version_due_parts.append(f'{version_link}<span style="color:#888">({", ".join(due_cvss_parts)})</span>')
                    else:
                        version_due_parts.append(version_link)

                versions_due_str = ", ".join(version_due_parts)

                # Check if any issue in this group has an urgent due date
                row_urgent = False
                for issue_data_check in group_data["issues"]:
                    if issue_data_check.get('duedate'):
                        try:
                            check_dt = datetime.strptime(issue_data_check['duedate'], "%Y-%m-%d")
                            if check_dt <= datetime.now() + timedelta(days=14):
                                row_urgent = True
                                break
                        except:
                            pass
                if row_urgent:
                    row_style = 'background-color:#fde8e8'
                else:
                    row_style = f'background-color:{"#fff" if idx % 2 == 0 else "#f9f9f9"}'
                html_rows.append(f"""<tr style="{row_style}"><td style="padding:2px;border-bottom:1px solid #eee">{cve_display}</td><td style="padding:2px;border-bottom:1px solid #eee">{description}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{phase_display}</td><td style="padding:2px;border-bottom:1px solid #eee">{assignees_list}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{num_versions}</td><td style="padding:2px;border-bottom:1px solid #eee;font-size:0.9em">{versions_due_str}</td></tr>""")
            else:
                # Non-CVE sections - show actual issue key or CVE ID
                first_issue_key = group_data['issues'][0]['key'] if group_data['issues'] else ""
                first_issue_url = f"{self.jira.url}/browse/{first_issue_key}" if first_issue_key else "#"

                issue_id = group_data.get("cve_id", "")
                if issue_id:
                    # Has CVE ID
                    issue_display = f'<a href="{first_issue_url}" style="color:#8e44ad;text-decoration:none;font-weight:bold">{issue_id}</a>'
                else:
                    # No CVE, show issue key as link
                    issue_display = f'<a href="{first_issue_url}" style="color:#666;text-decoration:none;font-weight:bold">{first_issue_key}</a>'

                row_style = f'background-color:{"#fff" if idx % 2 == 0 else "#f9f9f9"}'
                html_rows.append(f"""<tr style="{row_style}"><td style="padding:2px;border-bottom:1px solid #eee">{issue_display}</td><td style="padding:2px;border-bottom:1px solid #eee">{description}</td><td style="padding:2px;border-bottom:1px solid #eee">{assignees_list}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{num_versions}</td><td style="padding:2px;border-bottom:1px solid #eee">{versions_str}</td></tr>""")

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

            if "sfdc_cases" in include_fields and issue["fields"].get(self.custom_fields["sfdc_cases_counter"]):
                sfdc = issue["fields"][self.custom_fields["sfdc_cases_counter"]]
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

    FILTERED_ASSIGNEES = {"kernel se", "kernel_se"}

    def _is_filtered_assignee(self, name):
        """Check if assignee should be filtered out (e.g., kernel SE)"""
        if not name:
            return False
        return name.strip().lower() in self.FILTERED_ASSIGNEES

    def _filter_out_filtered_assignees(self, issues):
        """Remove issues whose sole assignee is a filtered assignee (e.g., kernel SE)"""
        return [
            issue for issue in issues
            if not self._is_filtered_assignee(
                issue["fields"].get("assignee", {}).get("displayName", "") if issue["fields"].get("assignee") else ""
            )
        ]

    def _get_fs_team_member_ids(self):
        """Build cached set of account IDs for all FS team members from active issue assignees"""
        if hasattr(self, '_cached_team_member_ids'):
            return self._cached_team_member_ids

        team_values = list(self.config.get("teams", {}).values())
        team_values_str = ", ".join(team_values)

        jql = f'project = {self.config["jira_project"]} AND AssignedTeam in ({team_values_str}) AND assignee is not EMPTY AND status not in (Closed, Done, Resolved)'
        result = self.jira.search_issues(jql, fields=["assignee"], max_results=500)

        member_ids = set()
        for issue in result.get("issues", []):
            assignee = issue["fields"].get("assignee")
            if assignee and assignee.get("accountId"):
                member_ids.add(assignee["accountId"])

        self._cached_team_member_ids = member_ids
        return member_ids

    def _shorten_name(self, full_name):
        """Shorten name from 'FirstName LastName' to 'F. LastName'"""
        if not full_name or full_name == "Unassigned":
            return full_name

        if self._is_filtered_assignee(full_name):
            return None

        parts = full_name.strip().split()
        if len(parts) == 1:
            return full_name

        return f"{parts[0][0]}. {' '.join(parts[1:])}"

    def generate_team_section(self, team_name, team_value):
        """Generate HTML section for one FS team"""
        html = [f"""<div style="margin-bottom:40px;border-left:5px solid #2c5aa0;padding:25px;border-radius:8px;background:linear-gradient(to right,#f8f9fa,#ffffff);box-shadow:0 2px 4px rgba(0,0,0,0.1)"><h2>📊 {team_name}</h2>"""]

        # Section 1: New & Closed Issues (TABLE FORMAT)
        new_issues = self._filter_out_filtered_assignees(self.get_new_issues(team_value))
        closed_issues = self._filter_out_filtered_assignees(self.get_closed_issues(team_value))

        # New Issues Table
        new_groups = self.group_issues_by_description(new_issues, include_severity=True)
        html.append(f'<h3 style="color:#1976d2;margin-top:20px">📌 New Issues (Last 24h): {len(new_groups)}</h3>')
        if new_groups:
            html.append(self.generate_table_format(new_groups, section_type="new"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No new issues</p>')

        # Closed Issues Table
        closed_groups = self.group_issues_by_description(closed_issues, include_severity=True)
        html.append(f'<h3 style="color:#388e3c">✅ Closed Issues (Last 24h): {len(closed_groups)}</h3>')
        if closed_groups:
            html.append(self.generate_table_format(closed_groups, section_type="closed"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No closed issues</p>')

        # Weekend Catch-Up (only on Mondays)
        if datetime.now().weekday() == 0:  # Monday
            weekend_new = self._filter_out_filtered_assignees(self.get_weekend_new_issues(team_value))
            weekend_closed = self._filter_out_filtered_assignees(self.get_weekend_closed_issues(team_value))

            html.append('<div style="background-color:#fffbf0;border-left:4px solid #f39c12;padding:15px;margin:20px 0">')
            html.append('<h4 style="color: #e67e22; margin-top: 0;">📅 Weekend (Fri-Sun)</h4>')

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
                                f'<a href="{issue_url}" style="color:#3498db;text-decoration:none" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                            )
                        html.append(f'<span style="color:#666;font-size:0.9em">→ {", ".join(version_links)}</span></li>')

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
                                f'<a href="{issue_url}" style="color:#3498db;text-decoration:none" title="{issue_data["status"]} - {issue_data["assignee"]}">{display_text}</a>'
                            )
                        html.append(f'<span style="color:#666;font-size:0.9em">→ {", ".join(version_links)}</span></li>')

                    html.append('</ul>')
            else:
                html.append('<p style="color:#666" style="margin: 10px 0;">No activity over the weekend</p>')

            html.append('</div>')

        # Section 2: CVE Issues (TABLE FORMAT)
        cve_issues = self._filter_out_filtered_assignees(self.get_cve_issues(team_value))
        cve_groups = self.group_cves(cve_issues)
        total_cve_issues = sum(len(g["issues"]) for g in cve_groups.values())
        unique_cve_count = len(cve_groups)
        html.append(f'<h3 style="color:#c62828">🔒 Active CVEs: {total_cve_issues} ({unique_cve_count} unique)</h3>')
        if cve_groups:
            html.append(self.generate_table_format(cve_groups, section_type="cve"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No active CVEs</p>')

        # Section 3: Prelim Testing Requested (TABLE FORMAT)
        prelim_testing = self._filter_out_filtered_assignees(self.get_prelim_testing_requested(team_value))
        prelim_groups = self.group_issues_by_description(prelim_testing)
        html.append(f'<h3 style="color:#7b1fa2">🧪 Prelim Testing Requested: {len(prelim_groups)}</h3>')
        if prelim_groups:
            html.append(self.generate_table_format(prelim_groups, section_type="prelim"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No prelim testing requested</p>')

        # Section 4: Integration Testing (TABLE FORMAT)
        integration_testing = self._filter_out_filtered_assignees(self.get_integration_testing(team_value))
        integration_groups = self.group_issues_by_description(integration_testing)
        html.append(f'<h3 style="color:#00897b">🔬 Integration Testing: {len(integration_groups)}</h3>')
        if integration_groups:
            html.append(self.generate_table_format(integration_groups, section_type="integration"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No integration testing issues</p>')

        # Section 4.5: Waiting on MR Merge (TABLE FORMAT)
        waiting_mr = self._filter_out_filtered_assignees(self.get_waiting_on_mr_merge(team_value))
        waiting_mr_groups = self.group_issues_by_description(waiting_mr)
        html.append(f'<h3 style="color:#f57c00">⏳ MR Attention (review, qe, waiting merge, other blockers): {len(waiting_mr_groups)}</h3>')
        if waiting_mr_groups:
            html.append(self.generate_table_format(waiting_mr_groups, section_type="waiting"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No issues waiting on MR merge</p>')

        # Section 5: Customer Escalations (TABLE FORMAT)
        escalations = self._filter_out_filtered_assignees(self.get_customer_escalations(team_value))
        html.append(f'<h3 style="color:#d73027">🚨 Customer Escalations: {len(escalations)}</h3>')
        if escalations:
            table_html = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Issue</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Summary</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Pri</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Assignee</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Updated</th></tr></thead><tbody>"""

            for idx, issue in enumerate(escalations):
                key = issue["key"]
                summary = issue["fields"]["summary"]
                issue_url = f"{self.jira.url}/browse/{key}"

                if len(summary) > 100:
                    summary = summary[:97] + "..."

                priority = issue["fields"].get("priority", {}).get("name", "N/A") if issue["fields"].get("priority") else "N/A"
                raw_assignee = issue["fields"].get("assignee", {}).get("displayName", "Unassigned") if issue["fields"].get("assignee") else "Unassigned"
                assignee = "Unassigned" if self._is_filtered_assignee(raw_assignee) else raw_assignee

                updated = issue["fields"].get("updated", "")
                if updated:
                    updated_dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                    updated_str = self._time_ago(updated_dt)
                else:
                    updated_str = "Unknown"

                # Priority color coding (Phase 3: shorter text)
                if priority == "Blocker":
                    priority_display = f'<span style="color:#d73027;font-weight:bold">Blk</span>'
                elif priority == "Critical":
                    priority_display = f'<span style="color:#e67e22;font-weight:bold">Crit</span>'
                elif priority == "Major":
                    priority_display = f'<span style="color:#f39c12">Maj</span>'
                else:
                    priority_display = priority[:3] if priority != "N/A" else "N/A"

                row_style = f'background-color:{"#fff" if idx % 2 == 0 else "#f9f9f9"}'
                table_html += f"""<tr style="{row_style}"><td style="padding:2px;border-bottom:1px solid #eee"><a href="{issue_url}" style="color:#3498db;text-decoration:none;font-weight:bold">{key}</a></td><td style="padding:2px;border-bottom:1px solid #eee">{summary}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{priority_display}</td><td style="padding:2px;border-bottom:1px solid #eee">{assignee}</td><td style="padding:2px;border-bottom:1px solid #eee">{updated_str}</td></tr>"""

            table_html += """</tbody></table>"""
            html.append(table_html)

        else:
            html.append('<p style="margin-left:20px;color:#666">No customer escalations</p>')

        # Section 5.5: Customer Bugs in NEW Status (TABLE FORMAT)
        customer_bugs_new = self._filter_out_filtered_assignees(self.get_customer_bugs_new(team_value))
        html.append(f'<h3 style="color:#e74c3c">🆕 Customer Bugs - (Needs Triage): {len(customer_bugs_new)}</h3>')
        if customer_bugs_new:
            # Generate table - Priority first, then other columns (with Phase)
            table_html = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Prio</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Issue</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Summary</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Phase</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Sev</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Created</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Last Updated</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Assignee</th></tr></thead><tbody>"""

            for idx, issue in enumerate(customer_bugs_new):
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

                # Check for SFDC cases (handle both string and dict formats)
                sfdc_cases = issue["fields"].get(self.custom_fields["sfdc_cases_counter"])
                has_sfdc = False
                if sfdc_cases:
                    if isinstance(sfdc_cases, str):
                        has_sfdc = True
                    elif isinstance(sfdc_cases, dict) and sfdc_cases.get("value"):
                        has_sfdc = True

                # Get severity
                severity_field = issue["fields"].get(self.custom_fields["severity"])
                severity = severity_field.get("value", "N/A") if severity_field else "N/A"

                # Get priority
                priority_field = issue["fields"].get("priority")
                priority = priority_field.get("name", "-") if priority_field else "-"

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

                # Get updated date
                updated = issue["fields"].get("updated", "")
                if updated:
                    updated_dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                    updated_str = self._time_ago(updated_dt)
                else:
                    updated_str = "Unknown"

                # Get assignee
                assignee = issue["fields"].get("assignee")
                assignee_name = self._shorten_name(assignee.get("displayName") if assignee else "Unassigned")
                if assignee_name is None:
                    assignee_name = "Unassigned"

                # Severity display with color
                if severity == "Critical":
                    severity_display = f'<span style="color:#d73027;font-weight:bold">Crit</span>'
                elif severity == "Important":
                    severity_display = f'<span style="color:#e67e22;font-weight:bold">Imp</span>'
                elif severity == "Moderate":
                    severity_display = f'<span style="color:#f39c12">Mod</span>'
                else:
                    severity_display = "-"

                # Priority display - abbreviated
                priority_abbrev = priority[:3] if priority != "-" else "-"

                # Age color coding
                if age_days > 60:
                    age_color = "#d73027"
                elif age_days > 30:
                    age_color = "#e67e22"
                else:
                    age_color = "#666"

                # Phase (status) display
                status_name = issue["fields"]["status"]["name"] if issue["fields"].get("status") else "New"
                phase_colors = {
                    "New": ("background:#dfe1e6;color:#44546f", "New"),
                    "In Progress": ("background:#deebff;color:#0747a6", "In Prog"),
                    "Planning": ("background:#eae6ff;color:#403294", "Plan"),
                    "Integration": ("background:#e3fcef;color:#006644", "Integr"),
                }
                p_style, p_text = phase_colors.get(status_name, ("background:#dfe1e6;color:#44546f", status_name[:6]))
                phase_badge = f'<span style="{p_style};padding:1px 5px;border-radius:3px;font-size:0.8em;font-weight:bold;white-space:nowrap">{p_text}</span>'

                row_style = f'background-color:{"#fff" if idx % 2 == 0 else "#f9f9f9"}'
                table_html += f"""<tr style="{row_style}"><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{priority_abbrev}</td><td style="padding:2px;border-bottom:1px solid #eee"><a href="{issue_url}" style="color:#3498db;text-decoration:none;font-weight:bold">{key}</a></td><td style="padding:2px;border-bottom:1px solid #eee">{summary}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{phase_badge}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{severity_display}</td><td style="padding:2px;border-bottom:1px solid #eee;color:{age_color}">{created_str} ({age_days}d)</td><td style="padding:2px;border-bottom:1px solid #eee">{updated_str}</td><td style="padding:2px;border-bottom:1px solid #eee">{assignee_name}</td></tr>"""

            table_html += """</tbody></table>"""
            html.append(table_html)

        else:
            html.append('<p style="margin-left:20px;color:#28a745">✅ No untriaged customer bugs</p>')

        # Section 5.55: Customer Bugs In Flight (all non-New statuses) (TABLE FORMAT)
        customer_bugs_ip = self._filter_out_filtered_assignees(self.get_customer_bugs_in_flight(team_value))
        html.append(f'<h3 style="color:#2c5aa0">🔧 Customer Bugs - (In Flight): {len(customer_bugs_ip)}</h3>')
        if customer_bugs_ip:
            table_html = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Prio</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Issue</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Summary</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Status</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0">Sev</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Created</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Last Updated</th><th style="padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0">Assignee</th></tr></thead><tbody>"""

            for idx, issue in enumerate(customer_bugs_ip):
                key = issue["key"]
                summary = issue["fields"]["summary"]
                issue_url = f"{self.jira.url}/browse/{key}"

                if len(summary) > 100:
                    summary = summary[:97] + "..."

                reporter = issue["fields"].get("reporter", {})
                reporter_name = reporter.get("displayName", "Unknown") if reporter else "Unknown"
                is_bugproxy = reporter_name == "bugproxy bugproxy"

                sfdc_cases = issue["fields"].get(self.custom_fields["sfdc_cases_counter"])
                has_sfdc = False
                if sfdc_cases:
                    if isinstance(sfdc_cases, str):
                        has_sfdc = True
                    elif isinstance(sfdc_cases, dict) and sfdc_cases.get("value"):
                        has_sfdc = True

                severity_field = issue["fields"].get(self.custom_fields["severity"])
                severity = severity_field.get("value", "N/A") if severity_field else "N/A"

                priority_field = issue["fields"].get("priority")
                priority = priority_field.get("name", "-") if priority_field else "-"

                created = issue["fields"].get("created", "")
                if created:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    created_str = created_dt.strftime("%b %d")
                    age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                else:
                    created_str = "Unknown"
                    age_days = 0

                updated = issue["fields"].get("updated", "")
                if updated:
                    updated_dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                    updated_str = self._time_ago(updated_dt)
                else:
                    updated_str = "Unknown"

                assignee = issue["fields"].get("assignee")
                assignee_name = self._shorten_name(assignee.get("displayName") if assignee else "Unassigned")
                if assignee_name is None:
                    assignee_name = "Unassigned"

                if severity == "Critical":
                    severity_display = f'<span style="color:#d73027;font-weight:bold">Crit</span>'
                elif severity == "Important":
                    severity_display = f'<span style="color:#e67e22;font-weight:bold">Imp</span>'
                elif severity == "Moderate":
                    severity_display = f'<span style="color:#f39c12">Mod</span>'
                else:
                    severity_display = "-"

                priority_abbrev = priority[:3] if priority != "-" else "-"

                status_field = issue["fields"].get("status", {})
                status_name = status_field.get("name", "Unknown") if status_field else "Unknown"
                status_colors = {
                    "In Progress": ("background:#deebff;color:#0747a6", "In Prog"),
                    "In Review": ("background:#e3fcef;color:#006644", "Review"),
                    "Testing": ("background:#fff3e0;color:#e65100", "Testing"),
                    "QE Review": ("background:#f3e5f5;color:#6a1b9a", "QE Rev"),
                    "Release Pending": ("background:#e8f5e9;color:#2e7d32", "Rel Pend"),
                    "Closed": ("background:#f0f0f0;color:#666", "Closed"),
                    "On QA": ("background:#fff8e1;color:#f57f17", "On QA"),
                }
                status_style, status_short = status_colors.get(status_name, ("background:#e0e0e0;color:#333", status_name[:8]))
                status_display = f'<span style="padding:1px 4px;border-radius:3px;font-size:0.85em;{status_style}">{status_short}</span>'

                if age_days > 60:
                    age_color = "#d73027"
                elif age_days > 30:
                    age_color = "#e67e22"
                else:
                    age_color = "#666"

                row_style = f'background-color:{"#fff" if idx % 2 == 0 else "#f9f9f9"}'
                table_html += f"""<tr style="{row_style}"><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{priority_abbrev}</td><td style="padding:2px;border-bottom:1px solid #eee"><a href="{issue_url}" style="color:#3498db;text-decoration:none;font-weight:bold">{key}</a></td><td style="padding:2px;border-bottom:1px solid #eee">{summary}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{status_display}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{severity_display}</td><td style="padding:2px;border-bottom:1px solid #eee;color:{age_color}">{created_str} ({age_days}d)</td><td style="padding:2px;border-bottom:1px solid #eee">{updated_str}</td><td style="padding:2px;border-bottom:1px solid #eee">{assignee_name}</td></tr>"""

            table_html += """</tbody></table>"""
            html.append(table_html)

        else:
            html.append('<p style="margin-left:20px;color:#28a745">✅ No customer bugs in flight</p>')

        # Section 5.6: Internal Bugs - Awaiting Triage (7+ days) (TABLE FORMAT)
        internal_bugs = self._filter_out_filtered_assignees(self.get_internal_bugs_awaiting_triage(team_value))
        html.append(f'<h3 style="color:#5c6bc0">📋 Internal Bugs - Awaiting Triage: {len(internal_bugs)}</h3>')
        if internal_bugs:
            th_style = "padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0"
            th_c_style = "padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0"
            table_html = f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em"><thead><tr><th style="{th_c_style}">Prio</th><th style="{th_style}">Issue</th><th style="{th_style}">Summary</th><th style="{th_c_style}">Phase</th><th style="{th_c_style}">Sev</th><th style="{th_style}">Age</th><th style="{th_style}">Assignee</th></tr></thead><tbody>"""

            # Sort by age (oldest first)
            def get_age(issue):
                created = issue["fields"].get("created", "")
                if created:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    return (datetime.now(created_dt.tzinfo) - created_dt).days
                return 0
            internal_bugs_sorted = sorted(internal_bugs, key=get_age, reverse=True)

            for idx, issue in enumerate(internal_bugs_sorted):
                key = issue["key"]
                summary = issue["fields"]["summary"]
                issue_url = f"{self.jira.url}/browse/{key}"

                if len(summary) > 100:
                    summary = summary[:97] + "..."

                priority_field = issue["fields"].get("priority")
                priority = priority_field.get("name", "-") if priority_field else "-"
                priority_abbrev = priority[:3] if priority != "-" else "-"

                severity_field = issue["fields"].get(self.custom_fields["severity"])
                severity = severity_field.get("value", "N/A") if severity_field else "N/A"

                if severity == "Critical":
                    severity_display = f'<span style="color:#d73027;font-weight:bold">Crit</span>'
                elif severity == "Important":
                    severity_display = f'<span style="color:#e67e22;font-weight:bold">Imp</span>'
                elif severity == "Moderate":
                    severity_display = f'<span style="color:#f39c12">Mod</span>'
                else:
                    severity_display = "-"

                # Phase (status) display
                status_name = issue["fields"]["status"]["name"] if issue["fields"].get("status") else "New"
                phase_colors = {
                    "New": ("background:#dfe1e6;color:#44546f", "New"),
                    "In Progress": ("background:#deebff;color:#0747a6", "In Prog"),
                    "Planning": ("background:#eae6ff;color:#403294", "Plan"),
                    "Integration": ("background:#e3fcef;color:#006644", "Integr"),
                }
                p_style, p_text = phase_colors.get(status_name, ("background:#dfe1e6;color:#44546f", status_name[:6]))
                phase_badge = f'<span style="{p_style};padding:1px 5px;border-radius:3px;font-size:0.8em;font-weight:bold;white-space:nowrap">{p_text}</span>'

                # Age
                created = issue["fields"].get("created", "")
                if created:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                else:
                    age_days = 0
                age_str = f"{age_days}d"

                # Assignee (shortened, filtered)
                assignee = issue["fields"].get("assignee")
                assignee_name = self._shorten_name(assignee.get("displayName") if assignee else "Unassigned")
                if assignee_name is None:
                    assignee_name = "Unassigned"

                row_style = f'background-color:{"#fff" if idx % 2 == 0 else "#f9f9f9"}'
                table_html += f"""<tr style="{row_style}"><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{priority_abbrev}</td><td style="padding:2px;border-bottom:1px solid #eee"><a href="{issue_url}" style="color:#3498db;text-decoration:none;font-weight:bold">{key}</a></td><td style="padding:2px;border-bottom:1px solid #eee">{summary}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{phase_badge}</td><td style="padding:2px;border-bottom:1px solid #eee;text-align:center">{severity_display}</td><td style="padding:2px;border-bottom:1px solid #eee">{age_str}</td><td style="padding:2px;border-bottom:1px solid #eee">{assignee_name}</td></tr>"""

            table_html += """</tbody></table>"""
            html.append(table_html)
        else:
            html.append('<p style="margin-left:20px;color:#666">No internal bugs awaiting triage</p>')

        # Section 6: Key Progress (TABLE FORMAT)
        progress = self._filter_out_filtered_assignees(self.get_key_progress(team_value))
        progress_groups = self.group_issues_by_description(progress)
        html.append(f'<h3 style="color:#1976d2">📈 Key Progress: {len(progress_groups)}</h3>')
        if progress_groups:
            html.append(self.generate_table_format(progress_groups, section_type="progress"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No key progress items</p>')

        # Section 7: Tasks (TABLE FORMAT)
        tasks = self._filter_out_filtered_assignees(self.get_tasks(team_value))
        task_groups = self.group_issues_by_description(tasks)
        html.append(f'<h3 style="color:#616161">📋 Tasks (Updated Last 24h): {len(task_groups)}</h3>')
        if task_groups:
            html.append(self.generate_table_format(task_groups, section_type="tasks"))
        else:
            html.append('<p style="margin-left:20px;color:#666">No active tasks</p>')

        html.append('</div>')
        return '\n'.join(html)

    def _collect_team_stats(self, team_value):
        """Collect all health stats for a team (shared by digest email and full report)"""
        new_issues = self._filter_out_filtered_assignees(self.get_new_issues(team_value))
        closed_issues = self._filter_out_filtered_assignees(self.get_closed_issues(team_value))
        new_groups = self.group_issues_by_description(new_issues)
        closed_groups = self.group_issues_by_description(closed_issues)

        cve_issues = self._filter_out_filtered_assignees(self.get_cve_issues(team_value))
        cve_groups = self.group_cves(cve_issues)
        cve_overdue = 0
        cve_soon = 0
        for gd in cve_groups.values():
            worst = "ok"
            for iss in gd["issues"]:
                dd = iss.get("duedate")
                if dd:
                    try:
                        days_left = (datetime.strptime(dd, "%Y-%m-%d") - datetime.now()).days
                        if days_left < 0:
                            worst = "overdue"
                        elif days_left <= 14 and worst != "overdue":
                            worst = "soon"
                    except Exception:
                        pass
            if worst == "overdue":
                cve_overdue += 1
            elif worst == "soon":
                cve_soon += 1

        escalations = self._filter_out_filtered_assignees(self.get_customer_escalations(team_value))
        cust_triage = self._filter_out_filtered_assignees(self.get_customer_bugs_new(team_value))
        cust_inflight = self._filter_out_filtered_assignees(self.get_customer_bugs_in_flight(team_value))
        prelim = self._filter_out_filtered_assignees(self.get_prelim_testing_requested(team_value))
        prelim_groups = self.group_issues_by_description(prelim)
        integration = self._filter_out_filtered_assignees(self.get_integration_testing(team_value))
        integ_groups = self.group_issues_by_description(integration)
        mr_waiting = self._filter_out_filtered_assignees(self.get_waiting_on_mr_merge(team_value))
        mr_groups = self.group_issues_by_description(mr_waiting)
        internal = self._filter_out_filtered_assignees(self.get_internal_bugs_awaiting_triage(team_value))
        progress = self._filter_out_filtered_assignees(self.get_key_progress(team_value))
        progress_groups = self.group_issues_by_description(progress)

        return {
            "new": len(new_groups),
            "closed": len(closed_groups),
            "cve": len(cve_groups),
            "cve_total": sum(len(g["issues"]) for g in cve_groups.values()),
            "cve_overdue": cve_overdue,
            "cve_soon": cve_soon,
            "esc": len(escalations),
            "cust_triage": len(cust_triage),
            "cust_inflight": len(cust_inflight),
            "prelim": len(prelim_groups),
            "integ": len(integ_groups),
            "mr": len(mr_groups),
            "internal": len(internal),
            "progress": len(progress_groups),
        }

    def generate_digest_email(self, confluence_page_id="512524957"):
        """Generate compact health-dashboard email with links to Confluence for details"""
        today = datetime.now().strftime("%B %d, %Y")
        is_monday = datetime.now().weekday() == 0
        confluence_url = f"https://redhat.atlassian.net/wiki/spaces/~622f0f4c8e5b380069e27ce0/pages/{confluence_page_id}"

        all_stats = []
        for team_name, team_value in self.config["teams"].items():
            try:
                stats = self._collect_team_stats(team_value)
                all_stats.append((team_name, stats))
            except Exception as e:
                print(f"  ERROR on {team_name}: {e}")
                all_stats.append((team_name, {k: 0 for k in [
                    "new", "closed", "cve", "cve_total", "cve_overdue", "cve_soon",
                    "esc", "cust_triage", "cust_inflight", "prelim", "integ", "mr", "internal", "progress"
                ]}))

        # Build the compact email
        html = [f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;color:#333;max-width:900px;margin:0 auto;padding:20px">
<h2 style="color:#2c3e50;margin-bottom:5px">FS Teams Health Dashboard — {today}{"  (Weekend)" if is_monday else ""}</h2>
<p style="margin:0 0 15px 0;color:#666;font-size:0.9em">
<a href="https://redhat.atlassian.net/jira/dashboards/25063" style="color:#3498db;text-decoration:none">Jira Dashboard</a>
&nbsp;|&nbsp;
<a href="{confluence_url}" style="color:#3498db;text-decoration:none;font-weight:bold">📄 Full Details on Confluence</a>
</p>"""]

        # Alerts banner
        alerts = []
        for team_name, s in all_stats:
            if s["cve_overdue"] > 0:
                alerts.append(f"<strong>{team_name}</strong>: {s['cve_overdue']} CVE(s) past SLA")
            if s["esc"] > 0:
                alerts.append(f"<strong>{team_name}</strong>: {s['esc']} escalation(s)")
        if alerts:
            html.append(f"""<div style="background:#fef3cd;border-left:4px solid #f39c12;padding:10px 15px;margin-bottom:15px;font-size:0.9em">
<strong>⚠ Attention:</strong> {" &nbsp;|&nbsp; ".join(alerts)}
</div>""")

        # Health summary table
        th = 'style="padding:6px 8px;border-bottom:2px solid #ccc;text-align:center;background:#f5f5f5;font-size:0.85em;white-space:nowrap"'
        th_l = 'style="padding:6px 8px;border-bottom:2px solid #ccc;text-align:left;background:#f5f5f5;font-size:0.85em"'

        html.append(f"""<table style="width:100%;border-collapse:collapse;border-spacing:0;font-size:0.9em">
<thead><tr>
<th {th_l}>Team</th>
<th {th}>📌 New Issues</th>
<th {th}>✅ Closed</th>
<th {th}>🔒 Open CVEs</th>
<th {th}>🚨 Escalations</th>
<th {th}>🆕 CU Issues In New</th>
<th {th}>🔧 CU Issues in Flight</th>
<th {th}>⏳ MR Pending</th>
<th {th}>📋 Internal Bugs</th>
</tr></thead><tbody>""")

        for idx, (team_name, s) in enumerate(all_stats):
            row_bg = "#fff" if idx % 2 == 0 else "#f9f9f9"
            td = f'style="padding:5px 8px;border-bottom:1px solid #eee;text-align:center;background:{row_bg}"'
            td_l = f'style="padding:5px 8px;border-bottom:1px solid #eee;text-align:left;background:{row_bg};font-weight:bold"'

            def cell(val, warn_threshold=None, critical_threshold=None, invert=False):
                if val == 0:
                    return f'<span style="color:#999">—</span>'
                color = "#333"
                if critical_threshold is not None and val >= critical_threshold:
                    color = "#d73027"
                elif warn_threshold is not None and val >= warn_threshold:
                    color = "#e67e22"
                if invert and val > 0:
                    color = "#28a745"
                return f'<span style="color:{color};font-weight:{"bold" if color != "#333" else "normal"}">{val}</span>'

            # CVE cell with overdue/soon indicator
            if s["cve"] == 0:
                cve_cell = '<span style="color:#999">—</span>'
            elif s["cve_overdue"] > 0:
                cve_cell = f'<span style="color:#d73027;font-weight:bold">{s["cve"]} ({s["cve_overdue"]}🔴)</span>'
            elif s["cve_soon"] > 0:
                cve_cell = f'<span style="color:#e67e22;font-weight:bold">{s["cve"]} ({s["cve_soon"]}🟡)</span>'
            else:
                cve_cell = f'{s["cve"]}'

            # New/Closed with direction hint
            new_cell = cell(s["new"])
            closed_cell = f'<span style="color:#28a745;font-weight:bold">{s["closed"]}</span>' if s["closed"] > 0 else '<span style="color:#999">—</span>'

            html.append(f"""<tr>
<td {td_l}><a href="{confluence_url}" style="color:#2c5aa0;text-decoration:none">{team_name}</a></td>
<td {td}>{new_cell}</td>
<td {td}>{closed_cell}</td>
<td {td}>{cve_cell}</td>
<td {td}>{cell(s["esc"], 1, 3)}</td>
<td {td}>{cell(s["cust_triage"], 3, 6)}</td>
<td {td}>{cell(s["cust_inflight"])}</td>
<td {td}>{cell(s["mr"], 3, 6)}</td>
<td {td}>{cell(s["internal"], 5, 10)}</td>
</tr>""")

        html.append("</tbody></table>")

        # Totals row
        totals = {}
        for key in ["new", "closed", "cve", "cve_overdue", "esc", "cust_triage", "cust_inflight", "mr", "internal"]:
            totals[key] = sum(s[key] for _, s in all_stats)

        # Footer with CTA
        html.append(f"""<p style="margin:20px 0 8px 0;text-align:center">
<a href="{confluence_url}" style="display:inline-block;background:#2c5aa0;color:white;padding:10px 24px;border-radius:5px;text-decoration:none;font-weight:bold;font-size:0.95em">
📄 View Full Details on Confluence →
</a>
</p>
<hr style="margin-top:20px;border:none;border-top:1px solid #ddd">
<p style="color:#333;font-size:0.95em;margin-top:15px">Regards,<br>Anand Reddy</p>
<p style="color:#999;font-size:0.85em;text-align:center;margin-top:15px">Generated by Daily PO Report System</p>
</body></html>""")

        return '\n'.join(html)

    def generate_report(self):
        """Generate complete HTML report for all teams"""
        today = datetime.now().strftime("%B %d, %Y")

        # CSS classes to replace inline styles (Phase 1 optimization)
        html = [f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{{font-family:Arial,sans-serif;line-height:1.4;color:#333;max-width:900px;margin:0 auto;padding:20px}}
h1{{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}}
h2{{color:#2c5aa0;border-bottom:3px solid #2c5aa0;padding-bottom:12px;margin-top:0;font-size:1.4em}}
h3{{margin-top:15px}}
a{{color:#3498db;text-decoration:none}}
a:hover{{text-decoration:underline}}
.dash-link{{color:#666;font-size:0.95em}}
.team-box{{margin-bottom:40px;border-left:5px solid #2c5aa0;padding:25px;border-radius:8px;background:linear-gradient(to right,#f8f9fa,#ffffff);box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
.table{{width:100%;border-collapse:collapse;border-spacing:0;margin-top:3px;font-size:0.9em}}
.th{{padding:2px;border-bottom:2px solid #ddd;text-align:left;background-color:#f0f0f0}}
.th-c{{padding:2px;border-bottom:2px solid #ddd;text-align:center;background-color:#f0f0f0}}
.td{{padding:2px;border-bottom:1px solid #eee;word-wrap:break-word}}
.td-c{{padding:2px;border-bottom:1px solid #eee;text-align:center}}
.td-sm{{padding:2px;border-bottom:1px solid #eee;font-size:0.9em}}
.row-0{{background-color:#fff}}
.row-1{{background-color:#f9f9f9}}
.link{{color:#3498db;text-decoration:none}}
.link-bold{{color:#3498db;text-decoration:none;font-weight:bold}}
.link-cve{{color:#d73027;text-decoration:none;font-weight:bold}}
.link-bug{{color:#666;text-decoration:none;font-weight:bold}}
.link-task{{color:#8e44ad;text-decoration:none;font-weight:bold}}
.sev-crit{{color:#d73027;font-weight:bold}}
.sev-imp{{color:#e67e22;font-weight:bold}}
.sev-mod{{color:#f39c12}}
.pri-blocker{{color:#d73027;font-weight:bold}}
.pri-critical{{color:#e67e22;font-weight:bold}}
.pri-major{{color:#f39c12}}
.due-over{{color:#d73027;font-weight:bold}}
.due-soon{{color:#e67e22;font-weight:bold}}
.age-old{{color:#d73027}}
.age-med{{color:#e67e22}}
.age-ok{{color:#666}}
.badge-ibm{{background-color:#3498db;color:white;padding:2px 4px;border-radius:2px;font-size:0.75em;font-weight:bold}}
.badge-sfdc{{background-color:#e67e22;color:white;padding:2px 4px;border-radius:2px;font-size:0.75em;font-weight:bold}}
.muted{{color:#666}}
.muted-sm{{color:#666;font-size:0.9em}}
.overflow{{margin-left:20px;color:#999;font-style:italic}}
.no-items{{margin-left:20px;color:#666}}
.success{{margin-left:20px;color:#28a745}}
.weekend-box{{background-color:#fffbf0;border-left:4px solid #f39c12;padding:15px;margin:20px 0}}
</style></head><body><p style="color:#666;font-size:0.95em">Dashboard: <a href="https://redhat.atlassian.net/jira/dashboards/25063">FS Team Dashboard</a></p>"""]

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

        html.append("""<hr style="margin-top:30px;border:none;border-top:1px solid #ddd"><p style="color:#333;font-size:0.95em;margin-top:20px">Regards,<br>Anand Reddy</p><p style="color:#999;font-size:0.9em;text-align:center;margin-top:20px">Generated by Daily PO Report System</p></body></html>""")

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

    def send_email(self, html_content, dry_run=False, force=False, subject=None):
        """Send email via SMTP"""
        # Check if already sent today (unless forced or dry-run)
        if not dry_run and not force and self.was_sent_today():
            print(f"ℹ Report already sent today. Skipping.")
            return

        today = datetime.now().strftime("%B %d, %Y")
        is_monday = datetime.now().weekday() == 0
        if subject is None:
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


def update_confluence_after_email(config_path, page_id, dry_run=False):
    """Update the Confluence FS-Digest page with today's data."""
    try:
        from confluence_digest import ConfluenceDigestGenerator, fetch_existing_page, update_confluence_page
        print("\n--- Updating Confluence page ---")
        gen = ConfluenceDigestGenerator(config_path)
        new_content = gen.generate()

        existing_body = ""
        page_info = None
        try:
            page_info = fetch_existing_page(page_id)
            existing_body = page_info["body"]
            print(f"Fetched existing page (version {page_info['version']})")
        except Exception as e:
            print(f"Could not fetch existing page: {e}")

        final_content = gen.build_with_archive(new_content, existing_body)
        print(f"Confluence content: {len(final_content)} chars")

        if dry_run:
            print("Dry-run — Confluence NOT updated.")
        elif page_info:
            update_confluence_page(page_id, page_info["title"], final_content, page_info["version"])
        else:
            print("Cannot update — no existing page info.")
    except Exception as e:
        print(f"⚠ Confluence update failed (email was still sent): {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Generate and send daily PO report")
    parser.add_argument("--dry-run", action="store_true", help="Generate report but don't send email")
    parser.add_argument("--force", action="store_true", help="Send even if already sent today")
    parser.add_argument("--check-only", action="store_true", help="Only check if report needed, don't send")
    parser.add_argument("--digest", action="store_true", help="Send compact health-dashboard email with Confluence link")
    parser.add_argument("--no-confluence", action="store_true", help="Skip Confluence page update")
    parser.add_argument("--confluence-page-id", default="512524957", help="Confluence page ID for detail links")
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
        if args.digest:
            html_content = generator.generate_digest_email(confluence_page_id=args.confluence_page_id)
            today = datetime.now().strftime("%B %d, %Y")
            is_monday = datetime.now().weekday() == 0
            digest_subject = f"FS Health Dashboard — {today}" + (" (Weekend)" if is_monday else "")
            generator.send_email(html_content, dry_run=args.dry_run, force=args.force, subject=digest_subject)
        else:
            html_content = generator.generate_report()
            generator.send_email(html_content, dry_run=args.dry_run, force=args.force)

        # Auto-update Confluence after email (unless --no-confluence)
        if not args.no_confluence:
            update_confluence_after_email(args.config, args.confluence_page_id, dry_run=args.dry_run)

    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
