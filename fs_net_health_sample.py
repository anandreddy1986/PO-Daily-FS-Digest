#!/usr/bin/env python3
"""
FS-Net Health Matrix - Sample Report
Focused on FS-Net team to validate and refine health metrics.
"""

import json
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


class FSNetHealthAnalyzer:
    """Analyzes FS-Net team health metrics"""

    def __init__(self, config_path="email_config.json"):
        self.config = self._load_config(config_path)
        self.jira = self._init_jira_client()
        self.custom_fields = self.config.get("custom_fields", {})
        self.script_dir = Path(__file__).parent
        self.team_value = "rhel-fs-net"  # FS-Net team

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

    def collect_metrics(self, days_back=30):
        """Collect comprehensive metrics for FS-Net"""
        print(f"\n📊 Collecting FS-Net metrics (last {days_back} days)...")
        print("=" * 70)

        metrics = {}

        # 1. Total Active Workload
        print("\n1️⃣  Active Workload (Open Issues)...")
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''

        fields = ["priority", "status", "issuetype", "created", "assignee",
                  self.custom_fields["severity"], "duedate"]
        result = self.jira.search_issues(jql, fields=fields, max_results=500)

        metrics['active_issues'] = result.get('issues', [])
        metrics['total_active'] = len(metrics['active_issues'])  # Use actual count
        print(f"   ✓ Total Active: {metrics['total_active']}")

        # 2. Velocity Metrics
        print("\n2️⃣  Velocity (New vs Closed)...")

        # New issues
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 created >= -{days_back}d'''
        result = self.jira.search_issues(jql, max_results=500)
        metrics['new_issues'] = result.get('issues', [])
        metrics['new_issues_count'] = len(metrics['new_issues'])  # Use actual count

        # Closed issues
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status changed to (Closed, Done, Resolved) DURING (-{days_back}d, now())'''
        result = self.jira.search_issues(jql, max_results=500)
        metrics['closed_issues'] = result.get('issues', [])
        metrics['closed_issues_count'] = len(metrics['closed_issues'])  # Use actual count

        velocity = metrics['closed_issues_count'] - metrics['new_issues_count']
        print(f"   ✓ New: {metrics['new_issues_count']}")
        print(f"   ✓ Closed: {metrics['closed_issues_count']}")
        print(f"   ✓ Velocity: {velocity:+d}")

        # 3. Security (CVEs)
        print("\n3️⃣  Security (Active CVEs)...")
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Vulnerability, Weakness) AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''
        result = self.jira.search_issues(jql, fields=fields, max_results=500)
        metrics['cve_issues'] = result.get('issues', [])
        metrics['active_cves'] = len(metrics['cve_issues'])  # Use actual count
        print(f"   ✓ Active CVEs: {metrics['active_cves']}")

        # 4. Customer Impact
        print("\n4️⃣  Customer Impact...")
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 (labels = "Escalation🔥" OR "Customer Impact" = "Customer Escalated") AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''
        result = self.jira.search_issues(jql, max_results=200)
        metrics['escalation_issues'] = result.get('issues', [])
        metrics['escalations'] = len(metrics['escalation_issues'])  # Use actual count
        print(f"   ✓ Escalations: {metrics['escalations']}")

        # 5. Workflow Status
        print("\n5️⃣  Workflow Distribution...")

        # Backlog (New)
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status = "New"'''
        result = self.jira.search_issues(jql, max_results=300)
        metrics['backlog'] = len(result.get('issues', []))

        # In Progress
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status = "In Progress"'''
        result = self.jira.search_issues(jql, max_results=300)
        metrics['in_progress'] = len(result.get('issues', []))

        # In Review
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 status = "In Review"'''
        result = self.jira.search_issues(jql, max_results=300)
        metrics['in_review'] = len(result.get('issues', []))

        print(f"   ✓ Backlog (New): {metrics['backlog']}")
        print(f"   ✓ In Progress: {metrics['in_progress']}")
        print(f"   ✓ In Review: {metrics['in_review']}")

        # 6. Aging Issues (Technical Debt)
        print("\n6️⃣  Aging Issues (90+ days old)...")
        jql = f'''project = {self.config["jira_project"]} AND
                 AssignedTeam = "{self.team_value}" AND
                 type in (Bug, Vulnerability, Story) AND
                 created <= -90d AND
                 status not in (Closed, Done, Resolved, "Release Pending")'''
        result = self.jira.search_issues(jql, max_results=500)
        metrics['aging_list'] = result.get('issues', [])
        metrics['aging_issues'] = len(metrics['aging_list'])  # Use actual count
        print(f"   ✓ Aging Issues: {metrics['aging_issues']}")

        # 7. Team Capacity
        print("\n7️⃣  Team Capacity...")
        assignees = set()
        assignee_workload = defaultdict(int)
        for issue in metrics['active_issues']:
            if issue['fields'].get('assignee'):
                name = issue['fields']['assignee']['displayName']
                assignees.add(name)
                assignee_workload[name] += 1

        metrics['active_contributors'] = len(assignees)
        metrics['assignee_workload'] = dict(assignee_workload)
        print(f"   ✓ Active Contributors: {metrics['active_contributors']}")

        # Top 5 contributors by workload
        top_contributors = sorted(assignee_workload.items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (name, count) in enumerate(top_contributors, 1):
            print(f"      {i}. {name}: {count} issues")

        # 8. Priority & Severity Analysis
        print("\n8️⃣  Priority & Severity Analysis...")
        metrics['priority_dist'] = self._analyze_priority(metrics['active_issues'])
        metrics['severity_dist'] = self._analyze_severity(metrics['cve_issues'])

        print("   Priority Distribution:")
        for priority, count in metrics['priority_dist'].items():
            if count > 0:
                print(f"      {priority}: {count}")

        print("   CVE Severity Distribution:")
        for severity, count in metrics['severity_dist'].items():
            if count > 0:
                print(f"      {severity}: {count}")

        return metrics

    def _analyze_priority(self, issues):
        """Analyze priority distribution"""
        dist = {'Blocker': 0, 'Critical': 0, 'Major': 0, 'Minor': 0, 'Undefined': 0}
        for issue in issues:
            priority = issue['fields'].get('priority')
            if priority:
                name = priority.get('name', 'Undefined')
                if name in dist:
                    dist[name] += 1
                else:
                    dist['Undefined'] += 1
            else:
                dist['Undefined'] += 1
        return dist

    def _analyze_severity(self, issues):
        """Analyze CVE severity distribution"""
        dist = {'Critical': 0, 'Important': 0, 'Moderate': 0, 'Low': 0, 'N/A': 0}
        for issue in issues:
            severity_field = issue['fields'].get(self.custom_fields["severity"])
            if severity_field:
                severity = severity_field.get('value', 'N/A')
                if severity in dist:
                    dist[severity] += 1
                else:
                    dist['N/A'] += 1
            else:
                dist['N/A'] += 1
        return dist

    def calculate_health_score(self, metrics):
        """Calculate health score with detailed breakdown"""
        print("\n" + "=" * 70)
        print("🏥 HEALTH SCORE CALCULATION")
        print("=" * 70)

        score = 100
        deductions = []

        # 1. Active workload volume
        if metrics['total_active'] > 150:
            deduct = 20
            deductions.append(f"High workload (>{150} issues): -{deduct}")
            score -= deduct
        elif metrics['total_active'] > 100:
            deduct = 10
            deductions.append(f"Moderate workload (>{100} issues): -{deduct}")
            score -= deduct

        # 2. Velocity
        velocity = metrics['closed_issues_count'] - metrics['new_issues_count']
        if velocity < 0:
            deduct = min(15, abs(velocity) * 0.5)
            deductions.append(f"Negative velocity ({velocity:+d}): -{deduct:.1f}")
            score -= deduct

        # 3. Escalations
        if metrics['escalations'] > 5:
            deduct = 20
            deductions.append(f"High escalations (>{5}): -{deduct}")
            score -= deduct
        elif metrics['escalations'] > 2:
            deduct = 10
            deductions.append(f"Multiple escalations (>{2}): -{deduct}")
            score -= deduct
        elif metrics['escalations'] > 0:
            deduct = 5
            deductions.append(f"Active escalations ({metrics['escalations']}): -{deduct}")
            score -= deduct

        # 4. Backlog
        if metrics['backlog'] > 50:
            deduct = 15
            deductions.append(f"Large backlog (>{50}): -{deduct}")
            score -= deduct
        elif metrics['backlog'] > 30:
            deduct = 10
            deductions.append(f"Growing backlog (>{30}): -{deduct}")
            score -= deduct

        # 5. Aging issues (technical debt)
        if metrics['aging_issues'] > 30:
            deduct = 15
            deductions.append(f"High technical debt (>{30} aging): -{deduct}")
            score -= deduct
        elif metrics['aging_issues'] > 15:
            deduct = 10
            deductions.append(f"Moderate technical debt (>{15} aging): -{deduct}")
            score -= deduct

        # 6. CVE load
        if metrics['active_cves'] > 20:
            deduct = 15
            deductions.append(f"High CVE load (>{20}): -{deduct}")
            score -= deduct
        elif metrics['active_cves'] > 10:
            deduct = 10
            deductions.append(f"Moderate CVE load (>{10}): -{deduct}")
            score -= deduct

        # 7. Critical/Blocker priority issues
        critical_count = metrics['priority_dist']['Blocker'] + metrics['priority_dist']['Critical']
        if critical_count > 10:
            deduct = 10
            deductions.append(f"High critical issues (>{10}): -{deduct}")
            score -= deduct

        score = max(0, min(100, score))

        print("\nDeductions:")
        if deductions:
            for d in deductions:
                print(f"  - {d}")
        else:
            print("  ✓ No deductions - Excellent health!")

        print(f"\n{'='*70}")
        print(f"FINAL HEALTH SCORE: {score}/100")

        if score >= 80:
            status = "🟢 HEALTHY"
        elif score >= 60:
            status = "🟡 MODERATE"
        else:
            status = "🔴 AT RISK"

        print(f"STATUS: {status}")
        print(f"{'='*70}\n")

        return score, deductions

    def generate_html_report(self, metrics, score, deductions):
        """Generate HTML report"""
        velocity = metrics['closed_issues_count'] - metrics['new_issues_count']

        if score >= 80:
            status, icon, color = "Healthy", "🟢", "#27ae60"
        elif score >= 60:
            status, icon, color = "Moderate", "🟡", "#f39c12"
        else:
            status, icon, color = "At Risk", "🔴", "#e74c3c"

        html = [f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid {color};
        }}
        .status-badge {{
            font-size: 2em;
            font-weight: bold;
            color: {color};
            text-align: center;
            margin: 20px 0;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .grid-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .grid-item .number {{
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }}
        .grid-item .label {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #34495e;
            color: white;
        }}
    </style>
</head>
<body>

<div class="header">
    <h1 style="margin: 0 0 10px 0;">FS-Net Health Assessment</h1>
    <p style="margin: 0; opacity: 0.9;">Sample Report for Metrics Validation | {datetime.now().strftime("%B %d, %Y")}</p>
</div>

<div class="metric-card">
    <h2 style="margin-top: 0;">Overall Health Status</h2>
    <div class="status-badge">{icon} {status}</div>
    <div style="text-align: center; font-size: 1.2em; color: #666;">
        Health Score: {score}/100
    </div>
</div>

<div class="metric-card">
    <h2 style="margin-top: 0;">📊 Key Metrics (Last 30 Days)</h2>
    <div class="grid">
        <div class="grid-item">
            <div class="number">{metrics['total_active']}</div>
            <div class="label">Active Issues</div>
        </div>
        <div class="grid-item">
            <div class="number" style="color: {'#27ae60' if velocity >= 0 else '#e74c3c'};">{velocity:+d}</div>
            <div class="label">Net Velocity</div>
        </div>
        <div class="grid-item">
            <div class="number" style="color: #e74c3c;">{metrics['active_cves']}</div>
            <div class="label">Active CVEs</div>
        </div>
        <div class="grid-item">
            <div class="number" style="color: {'#e74c3c' if metrics['escalations'] > 0 else '#27ae60'};">{metrics['escalations']}</div>
            <div class="label">Escalations</div>
        </div>
    </div>
</div>

<div class="metric-card">
    <h3 style="margin-top: 0;">Velocity Details</h3>
    <div class="grid">
        <div class="grid-item">
            <div class="number" style="color: #e74c3c;">{metrics['new_issues_count']}</div>
            <div class="label">New Issues</div>
        </div>
        <div class="grid-item">
            <div class="number" style="color: #27ae60;">{metrics['closed_issues_count']}</div>
            <div class="label">Closed Issues</div>
        </div>
    </div>
</div>

<div class="metric-card">
    <h3 style="margin-top: 0;">Workflow Status</h3>
    <div class="grid">
        <div class="grid-item">
            <div class="number">{metrics['backlog']}</div>
            <div class="label">Backlog (New)</div>
        </div>
        <div class="grid-item">
            <div class="number">{metrics['in_progress']}</div>
            <div class="label">In Progress</div>
        </div>
        <div class="grid-item">
            <div class="number">{metrics['in_review']}</div>
            <div class="label">In Review</div>
        </div>
        <div class="grid-item">
            <div class="number" style="color: {'#e74c3c' if metrics['aging_issues'] > 30 else '#f39c12' if metrics['aging_issues'] > 15 else '#27ae60'};">
                {metrics['aging_issues']}
            </div>
            <div class="label">Aging (90d+)</div>
        </div>
    </div>
</div>

<div class="metric-card">
    <h3 style="margin-top: 0;">Priority Distribution</h3>
    <table>
        <tr>
            <th>Priority</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
"""]

        total_active = metrics['total_active'] or 1  # Avoid division by zero
        for priority in ['Blocker', 'Critical', 'Major', 'Minor', 'Undefined']:
            count = metrics['priority_dist'][priority]
            pct = (count / total_active * 100) if total_active > 0 else 0
            html.append(f"""
        <tr>
            <td>{priority}</td>
            <td>{count}</td>
            <td>{pct:.1f}%</td>
        </tr>
""")

        html.append("""
    </table>
</div>

<div class="metric-card">
    <h3 style="margin-top: 0;">CVE Severity Distribution</h3>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
""")

        for severity in ['Critical', 'Important', 'Moderate', 'Low', 'N/A']:
            count = metrics['severity_dist'][severity]
            if count > 0:
                html.append(f"""
        <tr>
            <td>{severity}</td>
            <td>{count}</td>
        </tr>
""")

        html.append("""
    </table>
</div>

<div class="metric-card">
    <h3 style="margin-top: 0;">Team Capacity</h3>
    <p><strong>Active Contributors:</strong> {}</p>
    <p><strong>Top Contributors by Workload:</strong></p>
    <table>
        <tr>
            <th>Contributor</th>
            <th>Active Issues</th>
        </tr>
""".format(metrics['active_contributors']))

        top_contributors = sorted(metrics['assignee_workload'].items(),
                                 key=lambda x: x[1], reverse=True)[:10]
        for name, count in top_contributors:
            html.append(f"""
        <tr>
            <td>{name}</td>
            <td>{count}</td>
        </tr>
""")

        html.append("""
    </table>
</div>

<div class="metric-card">
    <h3 style="margin-top: 0;">🏥 Health Score Breakdown</h3>
    <p><strong>Starting Score:</strong> 100</p>
    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
""")

        if deductions:
            html.append("<p><strong>Deductions:</strong></p><ul>")
            for d in deductions:
                html.append(f"<li>{d}</li>")
            html.append("</ul>")
        else:
            html.append("<p style='color: #27ae60;'>✓ No deductions - Excellent health!</p>")

        html.append(f"""
    </div>
    <p style="font-size: 1.2em; margin-top: 15px;"><strong>Final Score: {score}/100</strong></p>
</div>

<div style="background-color: white; padding: 20px; border-radius: 8px; margin-top: 30px;">
    <p><strong>Report Generated:</strong> {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
    <p><strong>Team:</strong> FS-Net (rhel-fs-net)</p>
    <p><strong>Period:</strong> Last 30 days</p>
    <p><strong>Dashboard:</strong> <a href="https://redhat.atlassian.net/jira/dashboards/25063">FS Team Dashboard</a></p>
</div>

</body>
</html>
""")

        return '\n'.join(html)


def main():
    try:
        print("\n" + "=" * 70)
        print("FS-NET HEALTH ASSESSMENT - SAMPLE REPORT")
        print("=" * 70)

        analyzer = FSNetHealthAnalyzer()

        # Collect metrics
        metrics = analyzer.collect_metrics(days_back=30)

        # Calculate health score
        score, deductions = analyzer.calculate_health_score(metrics)

        # Generate HTML report
        html = analyzer.generate_html_report(metrics, score, deductions)

        # Save report
        output_path = analyzer.script_dir / "fs_net_health_sample.html"
        with open(output_path, 'w') as f:
            f.write(html)

        print(f"\n✓ Report saved to: {output_path}")
        print("\n" + "=" * 70)
        print("REVIEW THE REPORT AND PROVIDE FEEDBACK:")
        print("  1. Are the metrics relevant?")
        print("  2. Is the health scoring algorithm reasonable?")
        print("  3. Any metrics missing or unnecessary?")
        print("  4. Should we adjust scoring thresholds?")
        print("=" * 70 + "\n")

    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
