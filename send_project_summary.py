#!/usr/bin/env python3
"""
Send Project Summary Email
Sends the project summary HTML document as an email attachment
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

def send_project_summary():
    """Send project summary as email attachment"""

    # Load config
    config_path = Path(__file__).parent / "email_config.json"
    with open(config_path, 'r') as f:
        config = json.load(f)

    # Email details
    sender = config.get("sender_email", config["recipient"])
    recipient = config["recipient"]
    subject = "FS Teams Daily Digest - Project Summary"

    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject

    # Email body
    body = """Hi Anand,

Please find attached the comprehensive project summary for the FS Teams Daily Digest automation system.

The document covers:
• Problem Statement - Manual dashboard checking inefficiency
• Solution Architecture - Agentic automation with JQL queries
• Technology Stack - Python, Jira REST API, SMTP, Cron scheduling
• Key Features - CVE tracking, customer escalations, intelligent grouping
• Implementation Journey - From concept to production
• Outcomes & Impact - Daily automated insights for 4 FS teams
• Technical Highlights - JQL queries and Python filtering strategies

The PDF can be opened in any PDF reader.

Regards,
Anand Reddy
"""

    msg.attach(MIMEText(body, 'plain'))

    # Attach PDF file
    pdf_file = Path(__file__).parent / "PROJECT_SUMMARY.pdf"

    with open(pdf_file, 'rb') as f:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(f.read())

    encoders.encode_base64(part)
    part.add_header(
        'Content-Disposition',
        f'attachment; filename=FS_Teams_Daily_Digest_Project_Summary.pdf'
    )

    msg.attach(part)

    # Send email via Red Hat SMTP
    smtp_server = config["smtp_server"]
    smtp_port = config["smtp_port"]

    try:
        # Try plain SMTP (port 25, no auth, no TLS)
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.send_message(msg)
        print(f"✓ Project summary sent successfully to {recipient}")
    except Exception as e:
        print(f"Port {smtp_port} failed, trying port 587 with STARTTLS...")
        # If that fails, try with STARTTLS on port 587
        with smtplib.SMTP(smtp_server, 587, timeout=10) as server:
            server.starttls()
            server.send_message(msg)
        print(f"✓ Project summary sent successfully to {recipient}")

if __name__ == "__main__":
    send_project_summary()
