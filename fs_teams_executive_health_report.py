#!/usr/bin/env python3
"""
FS Teams Executive Health & Capacity Report
Generates comprehensive health and capacity assessment for all 4 FS teams.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import requests
from requests.auth import HTTPBasicAuth


class JiraClient:
    """Jira API client for querying issues"""

    def __init__(self, url, username, api_token):
        self.url = url.rstrip('/')
        self.auth = HTTPBasicAuth(username, api_token)
        self.headers = {"Accept": "application/json"}

    def search_issues(self, jql, fields=None, max_results=200):
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


class FSTeamsHealthReport:
    """Generates executive health and capacity report for all FS teams"""

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

    def get_team_metrics(self, team_value, days_back=30):
        """Get comprehensive metrics for a team"""
        metrics = {}

        # 1. Active workload (open issues by priority)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["priority", "status", "issuetype", "created", "assignee", self.custom_fields["severity"]]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        metrics['total_active'] = result.get('total', 0)
        metrics['active_issues'] = result.get('issues', [])

        # 2. New issues (last N days)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 created >= -{days_back}d'''
        result = self.jira.search_issues(jql, max_results=500)
        metrics['new_issues_count'] = result.get('total', 0)
        metrics['new_issues'] = result.get('issues', [])

        # 3. Closed issues (last N days)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status changed to (Closed, Done, Resolved) DURING (-{days_back}d, now())'''
        result = self.jira.search_issues(jql, max_results=500)
        metrics['closed_issues_count'] = result.get('total', 0)
        metrics['closed_issues'] = result.get('issues', [])

        # 4. CVEs (active security vulnerabilities)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Vulnerability, Weakness) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''
        result = self.jira.search_issues(jql, fields=fields, max_results=500)
        metrics['active_cves'] = result.get('total', 0)
        metrics['cve_issues'] = result.get('issues', [])

        # 5. Customer escalations
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 (labels = "Escalation🔥" OR "Customer Impact" = "Customer Escalated") AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''
        result = self.jira.search_issues(jql, max_results=200)
        metrics['escalations'] = result.get('total', 0)

        # 6. In Progress items
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status = "In Progress"'''
        result = self.jira.search_issues(jql, max_results=300)
        metrics['in_progress'] = result.get('total', 0)

        # 7. Backlog (New status)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status = "New"'''
        result = self.jira.search_issues(jql, max_results=300)
        metrics['backlog'] = result.get('total', 0)

        # 8. Aging issues (>90 days old)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 created <= -{days_back * 3}d AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''
        result = self.jira.search_issues(jql, max_results=500)
        metrics['aging_issues'] = result.get('total', 0)

        # 9. Get active contributors (unique assignees)
        assignees = set()
        for issue in metrics['active_issues']:
            if issue['fields'].get('assignee'):
                assignees.add(issue['fields']['assignee']['displayName'])
        metrics['active_contributors'] = len(assignees)

        return metrics

    def analyze_priority_distribution(self, issues):
        """Analyze priority distribution of issues"""
        distribution = {
            'Blocker': 0,
            'Critical': 0,
            'Major': 0,
            'Minor': 0,
            'Undefined': 0
        }

        for issue in issues:
            priority = issue['fields'].get('priority')
            if priority:
                priority_name = priority.get('name', 'Undefined')
                if priority_name in distribution:
                    distribution[priority_name] += 1
                else:
                    distribution['Undefined'] += 1
            else:
                distribution['Undefined'] += 1

        return distribution

    def analyze_severity_distribution(self, issues):
        """Analyze severity distribution for CVEs"""
        distribution = {
            'Critical': 0,
            'Important': 0,
            'Moderate': 0,
            'Low': 0,
            'N/A': 0
        }

        for issue in issues:
            severity_field = issue['fields'].get(self.custom_fields["severity"])
            if severity_field:
                severity = severity_field.get('value', 'N/A')
                if severity in distribution:
                    distribution[severity] += 1
                else:
                    distribution['N/A'] += 1
            else:
                distribution['N/A'] += 1

        return distribution

    def calculate_health_score(self, metrics):
        """Calculate a health score (0-100) based on metrics"""
        score = 100

        # Deduct points for various risk factors

        # 1. High volume of active issues (>100 = concerning)
        if metrics['total_active'] > 150:
            score -= 20
        elif metrics['total_active'] > 100:
            score -= 10

        # 2. Negative velocity (more new than closed)
        if metrics['new_issues_count'] > metrics['closed_issues_count']:
            delta = metrics['new_issues_count'] - metrics['closed_issues_count']
            score -= min(15, delta * 0.5)

        # 3. High escalation count
        if metrics['escalations'] > 5:
            score -= 20
        elif metrics['escalations'] > 2:
            score -= 10
        elif metrics['escalations'] > 0:
            score -= 5

        # 4. Large backlog
        if metrics['backlog'] > 50:
            score -= 15
        elif metrics['backlog'] > 30:
            score -= 10

        # 5. Aging issues (technical debt)
        if metrics['aging_issues'] > 30:
            score -= 15
        elif metrics['aging_issues'] > 15:
            score -= 10

        # 6. CVE load
        if metrics['active_cves'] > 20:
            score -= 15
        elif metrics['active_cves'] > 10:
            score -= 10

        return max(0, min(100, score))

    def get_health_status(self, score):
        """Convert health score to status"""
        if score >= 80:
            return "Healthy", "🟢", "#27ae60"
        elif score >= 60:
            return "Moderate", "🟡", "#f39c12"
        else:
            return "At Risk", "🔴", "#e74c3c"

    def get_capacity_status(self, metrics):
        """Determine capacity status based on workload vs throughput"""
        # Calculate capacity indicator
        total_load = metrics['total_active'] + metrics['backlog']
        velocity = metrics['closed_issues_count'] - metrics['new_issues_count']

        if velocity > 0 and total_load < 100:
            return "Available", "🟢", "#27ae60"
        elif velocity >= 0 or total_load < 150:
            return "At Capacity", "🟡", "#f39c12"
        else:
            return "Over Capacity", "🔴", "#e74c3c"

    def generate_team_summary(self, team_name, team_value, metrics):
        """Generate HTML summary for one team"""
        health_score = self.calculate_health_score(metrics)
        health_status, health_icon, health_color = self.get_health_status(health_score)
        capacity_status, capacity_icon, capacity_color = self.get_capacity_status(metrics)

        # Priority distribution
        priority_dist = self.analyze_priority_distribution(metrics['active_issues'])

        # Severity distribution for CVEs
        severity_dist = self.analyze_severity_distribution(metrics['cve_issues'])

        html = [f"""
<div style="border: 2px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 25px; background-color: #f9f9f9;">
    <h2 style="color: #2c3e50; margin-top: 0; border-bottom: 2px solid {health_color}; padding-bottom: 10px;">
        {team_name}
    </h2>

    <!-- Status Indicators -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 20px;">
        <div style="background-color: white; padding: 15px; border-radius: 5px; border-left: 4px solid {health_color};">
            <div style="font-size: 0.9em; color: #666; margin-bottom: 5px;">Overall Health</div>
            <div style="font-size: 1.5em; font-weight: bold; color: {health_color};">
                {health_icon} {health_status}
            </div>
            <div style="font-size: 0.85em; color: #666; margin-top: 5px;">Score: {health_score}/100</div>
        </div>
        <div style="background-color: white; padding: 15px; border-radius: 5px; border-left: 4px solid {capacity_color};">
            <div style="font-size: 0.9em; color: #666; margin-bottom: 5px;">Capacity Status</div>
            <div style="font-size: 1.5em; font-weight: bold; color: {capacity_color};">
                {capacity_icon} {capacity_status}
            </div>
            <div style="font-size: 0.85em; color: #666; margin-top: 5px;">{metrics['active_contributors']} active contributors</div>
        </div>
    </div>

    <!-- Key Metrics -->
    <div style="background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
        <h3 style="color: #34495e; margin-top: 0; font-size: 1.1em;">📊 Workload Metrics (Last 30 Days)</h3>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; text-align: center;">
            <div>
                <div style="font-size: 1.8em; font-weight: bold; color: #3498db;">{metrics['total_active']}</div>
                <div style="font-size: 0.85em; color: #666;">Active Issues</div>
            </div>
            <div>
                <div style="font-size: 1.8em; font-weight: bold; color: #e74c3c;">{metrics['new_issues_count']}</div>
                <div style="font-size: 0.85em; color: #666;">New Issues</div>
            </div>
            <div>
                <div style="font-size: 1.8em; font-weight: bold; color: #27ae60;">{metrics['closed_issues_count']}</div>
                <div style="font-size: 0.85em; color: #666;">Closed Issues</div>
            </div>
            <div>
                <div style="font-size: 1.8em; font-weight: bold; color: {'#e74c3c' if metrics['new_issues_count'] > metrics['closed_issues_count'] else '#27ae60'};">
                    {metrics['closed_issues_count'] - metrics['new_issues_count']:+d}
                </div>
                <div style="font-size: 0.85em; color: #666;">Net Velocity</div>
            </div>
        </div>
    </div>

    <!-- Priority & Severity -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
        <div style="background-color: white; padding: 15px; border-radius: 5px;">
            <h4 style="color: #34495e; margin-top: 0; font-size: 1em;">Priority Distribution</h4>
            <div style="font-size: 0.9em;">
                <div style="margin: 5px 0;">🔴 Blocker: <strong>{priority_dist['Blocker']}</strong></div>
                <div style="margin: 5px 0;">🟠 Critical: <strong>{priority_dist['Critical']}</strong></div>
                <div style="margin: 5px 0;">🟡 Major: <strong>{priority_dist['Major']}</strong></div>
                <div style="margin: 5px 0;">🔵 Minor: <strong>{priority_dist['Minor']}</strong></div>
                <div style="margin: 5px 0; color: #999;">⚪ Undefined: {priority_dist['Undefined']}</div>
            </div>
        </div>
        <div style="background-color: white; padding: 15px; border-radius: 5px;">
            <h4 style="color: #34495e; margin-top: 0; font-size: 1em;">Security (CVEs)</h4>
            <div style="font-size: 1.5em; font-weight: bold; color: #e74c3c; margin-bottom: 10px;">
                {metrics['active_cves']} Active
            </div>
            <div style="font-size: 0.85em;">
                <div style="margin: 3px 0;">Critical: {severity_dist['Critical']} | Important: {severity_dist['Important']}</div>
                <div style="margin: 3px 0; color: #666;">Moderate: {severity_dist['Moderate']} | Low: {severity_dist['Low']}</div>
            </div>
        </div>
    </div>

    <!-- Risk Indicators -->
    <div style="background-color: white; padding: 15px; border-radius: 5px;">
        <h4 style="color: #34495e; margin-top: 0; font-size: 1em;">⚠️ Risk Indicators</h4>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; text-align: center; font-size: 0.9em;">
            <div>
                <div style="font-size: 1.3em; font-weight: bold; color: {'#e74c3c' if metrics['escalations'] > 0 else '#27ae60'};">
                    {metrics['escalations']}
                </div>
                <div style="color: #666;">Escalations</div>
            </div>
            <div>
                <div style="font-size: 1.3em; font-weight: bold; color: {'#e74c3c' if metrics['backlog'] > 50 else '#f39c12' if metrics['backlog'] > 30 else '#27ae60'};">
                    {metrics['backlog']}
                </div>
                <div style="color: #666;">Backlog (New)</div>
            </div>
            <div>
                <div style="font-size: 1.3em; font-weight: bold; color: {'#e74c3c' if metrics['aging_issues'] > 30 else '#f39c12' if metrics['aging_issues'] > 15 else '#27ae60'};">
                    {metrics['aging_issues']}
                </div>
                <div style="color: #666;">Aging (90d+)</div>
            </div>
            <div>
                <div style="font-size: 1.3em; font-weight: bold; color: #3498db;">
                    {metrics['in_progress']}
                </div>
                <div style="color: #666;">In Progress</div>
            </div>
        </div>
    </div>
</div>
"""]

        return '\n'.join(html)

    def generate_consolidated_overview(self, all_metrics):
        """Generate consolidated overview section"""
        total_active = sum(m['total_active'] for m in all_metrics.values())
        total_new = sum(m['new_issues_count'] for m in all_metrics.values())
        total_closed = sum(m['closed_issues_count'] for m in all_metrics.values())
        total_cves = sum(m['active_cves'] for m in all_metrics.values())
        total_escalations = sum(m['escalations'] for m in all_metrics.values())
        total_contributors = sum(m['active_contributors'] for m in all_metrics.values())

        # Overall health
        health_scores = {team: self.calculate_health_score(metrics)
                        for team, metrics in all_metrics.items()}
        avg_health = sum(health_scores.values()) / len(health_scores)
        overall_status, overall_icon, overall_color = self.get_health_status(avg_health)

        html = [f"""
<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px;">
    <h1 style="margin: 0 0 10px 0; font-size: 2em;">FS Teams: Consolidated Health & Capacity Assessment</h1>
    <div style="font-size: 1.1em; opacity: 0.9;">All 4 File Systems Teams | {datetime.now().strftime("%B %d, %Y")}</div>
</div>

<div style="background-color: white; border: 3px solid {overall_color}; border-radius: 10px; padding: 25px; margin-bottom: 30px;">
    <h2 style="color: #2c3e50; margin-top: 0; text-align: center;">🎯 Executive Summary</h2>

    <div style="text-align: center; margin: 20px 0;">
        <div style="font-size: 2.5em; font-weight: bold; color: {overall_color};">
            {overall_icon} {overall_status}
        </div>
        <div style="font-size: 1.2em; color: #666; margin-top: 10px;">
            Overall Health Score: {avg_health:.1f}/100
        </div>
    </div>

    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 25px;">
        <div style="text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 8px;">
            <div style="font-size: 2em; font-weight: bold; color: #3498db;">{total_active}</div>
            <div style="color: #666; margin-top: 5px;">Total Active Issues</div>
            <div style="font-size: 0.85em; color: #999; margin-top: 3px;">Across all FS teams</div>
        </div>
        <div style="text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 8px;">
            <div style="font-size: 2em; font-weight: bold; color: {'#27ae60' if total_closed >= total_new else '#e74c3c'};">
                {total_closed - total_new:+d}
            </div>
            <div style="color: #666; margin-top: 5px;">Net Velocity (30d)</div>
            <div style="font-size: 0.85em; color: #999; margin-top: 3px;">{total_new} new, {total_closed} closed</div>
        </div>
        <div style="text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 8px;">
            <div style="font-size: 2em; font-weight: bold; color: #e74c3c;">{total_cves}</div>
            <div style="color: #666; margin-top: 5px;">Active CVEs</div>
            <div style="font-size: 0.85em; color: #999; margin-top: 3px;">Security vulnerabilities</div>
        </div>
    </div>

    <div style="margin-top: 25px; padding: 15px; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px;">
        <strong>🚨 Critical Attention:</strong> {total_escalations} active customer escalations |
        {total_contributors} active contributors across all teams
    </div>
</div>

<div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
    <h3 style="color: #2c3e50; margin-top: 0;">📊 Team Health Comparison</h3>
    <table style="width: 100%; border-collapse: collapse;">
        <thead>
            <tr style="background-color: #34495e; color: white;">
                <th style="padding: 12px; text-align: left;">Team</th>
                <th style="padding: 12px; text-align: center;">Health</th>
                <th style="padding: 12px; text-align: center;">Score</th>
                <th style="padding: 12px; text-align: center;">Active Issues</th>
                <th style="padding: 12px; text-align: center;">Velocity</th>
                <th style="padding: 12px; text-align: center;">CVEs</th>
                <th style="padding: 12px; text-align: center;">Escalations</th>
            </tr>
        </thead>
        <tbody>
"""]

        # Add rows for each team
        for team_name, metrics in all_metrics.items():
            score = health_scores[team_name]
            status, icon, color = self.get_health_status(score)
            velocity = metrics['closed_issues_count'] - metrics['new_issues_count']

            html.append(f"""
            <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 12px; font-weight: bold;">{team_name}</td>
                <td style="padding: 12px; text-align: center;">{icon} {status}</td>
                <td style="padding: 12px; text-align: center; color: {color}; font-weight: bold;">{score}</td>
                <td style="padding: 12px; text-align: center;">{metrics['total_active']}</td>
                <td style="padding: 12px; text-align: center; color: {'#27ae60' if velocity >= 0 else '#e74c3c'}; font-weight: bold;">
                    {velocity:+d}
                </td>
                <td style="padding: 12px; text-align: center;">{metrics['active_cves']}</td>
                <td style="padding: 12px; text-align: center; color: {'#e74c3c' if metrics['escalations'] > 0 else '#27ae60'};">
                    {metrics['escalations']}
                </td>
            </tr>
""")

        html.append("""
        </tbody>
    </table>
</div>
""")

        return '\n'.join(html)

    def generate_report(self):
        """Generate complete executive health report"""
        all_metrics = {}

        # Collect metrics for all teams
        for team_name, team_value in self.config["teams"].items():
            try:
                print(f"Collecting metrics for {team_name}...")
                all_metrics[team_name] = self.get_team_metrics(team_value)
            except Exception as e:
                print(f"ERROR fetching {team_name}: {str(e)}")
                # Create empty metrics on error
                all_metrics[team_name] = {
                    'total_active': 0, 'new_issues_count': 0, 'closed_issues_count': 0,
                    'active_cves': 0, 'escalations': 0, 'in_progress': 0, 'backlog': 0,
                    'aging_issues': 0, 'active_contributors': 0, 'active_issues': [],
                    'cve_issues': []
                }

        # Build HTML report
        html = ["""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
    </style>
</head>
<body>
"""]

        # Consolidated overview
        html.append(self.generate_consolidated_overview(all_metrics))

        # Individual team sections
        html.append('<h2 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-top: 40px;">📋 Individual Team Assessments</h2>')

        for team_name, team_value in self.config["teams"].items():
            try:
                html.append(self.generate_team_summary(team_name, team_value, all_metrics[team_name]))
            except Exception as e:
                html.append(f"""
<div style="border: 2px solid #e74c3c; border-radius: 8px; padding: 20px; margin-bottom: 25px; background-color: #fee;">
    <h2 style="color: #e74c3c;">⚠️ {team_name} - Error</h2>
    <p>Failed to generate report: {str(e)}</p>
</div>
""")

        # Footer
        html.append(f"""
<hr style="margin-top: 40px; border: none; border-top: 2px solid #ddd;">
<div style="background-color: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
    <h3 style="color: #34495e; margin-top: 0;">📝 Report Information</h3>
    <p><strong>Generated:</strong> {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
    <p><strong>Period:</strong> Last 30 days</p>
    <p><strong>Teams Covered:</strong> FS-Net, FS-local, FS-VFS, FS-GFS2</p>
    <p><strong>Dashboard:</strong> <a href="https://redhat.atlassian.net/jira/dashboards/25063">FS Team Dashboard</a></p>
    <p><strong>Prepared By:</strong> Anand Reddy (anareddy@redhat.com)</p>
</div>
</body>
</html>
""")

        return '\n'.join(html)

    def save_report(self, html_content, filename="fs_teams_health_report.html"):
        """Save HTML report to file"""
        output_path = self.script_dir / filename
        with open(output_path, 'w') as f:
            f.write(html_content)
        print(f"✓ Report saved to: {output_path}")
        return output_path


def main():
    try:
        print("FS Teams Executive Health & Capacity Report")
        print("=" * 60)

        generator = FSTeamsHealthReport()
        html_content = generator.generate_report()
        output_path = generator.save_report(html_content)

        print("\n" + "=" * 60)
        print(f"✓ Report generated successfully!")
        print(f"📄 Open in browser: {output_path}")

    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
