import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import requests
import os
import json
import matplotlib.pyplot as plt
from collections import Counter

# === Config ===
RESULTS_DIR = r"E:\html\Cyber\pcap-lab\results"
ALERT_EMAIL = "madhavvviswanath@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "madhavvviswanath@gmail.com"
SMTP_PASS = "fpsd nzmk psim llnn"   # Gmail App Password

# VirusTotal API
VT_API_KEY = "ef52e228de3ed4fef2cabc2a09644d63b9a0f59a7770e0f4db4d816821c9cbc7"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


def send_email_alert(subject, body_html, images):
    """Send email with inline charts + HTML report"""
    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL

    alt = MIMEMultipart("alternative")
    msg.attach(alt)

    alt.attach(MIMEText(body_html, "html"))

    # Attach inline images
    for cid, img_path in images.items():
        with open(img_path, "rb") as f:
            img = MIMEImage(f.read())
            img.add_header("Content-ID", f"<{cid}>")
            msg.attach(img)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def check_virustotal(ip):
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(VT_URL.format(ip), headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        return data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    return -1


def analyze_results():
    report_sections = []
    all_ips = []
    malicious_ips = []
    file_summary = []

    # === Process each file ===
    for file in os.listdir(RESULTS_DIR):
        if file.endswith(".json"):
            path = os.path.join(RESULTS_DIR, file)

            with open(path, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = pd.json_normalize(data)

            if not df.empty:
                suspicious_count = len(df)
                file_summary.append((file, suspicious_count))

                section_html = f"<h3>File: {file}</h3>"
                section_html += f"<p>Suspicious entries: <b>{suspicious_count}</b></p>"

                if "id.resp_h" in df.columns:
                    ips = df["id.resp_h"].dropna().unique()
                    section_html += "<ul>"
                    for ip in ips:
                        all_ips.append(ip)
                        malicious = check_virustotal(ip)
                        if malicious > 0:
                            malicious_ips.append(ip)
                            section_html += f"<li><b style='color:red;'>Malicious IP:</b> {ip} (Detections: {malicious})</li>"
                        else:
                            section_html += f"<li>Clean IP: {ip}</li>"
                    section_html += "</ul>"

                report_sections.append(section_html)

    # === Insights ===
    ip_counts = Counter(all_ips)
    top_ips = ip_counts.most_common(5)

    insight_html = "<h2>🔎 Insights</h2>"
    if malicious_ips:
        malicious_corr = Counter(malicious_ips)
        worst_ip, worst_count = malicious_corr.most_common(1)[0]
        insight_html += f"<p>⚠️ The IP <b>{worst_ip}</b> appeared in <b>{worst_count}</b> different files and was flagged malicious.</p>"
    else:
        insight_html += "<p>No malicious IP correlation found.</p>"

    if top_ips:
        insight_html += "<p>📌 Top 5 Contacted IPs:</p><ol>"
        for ip, cnt in top_ips:
            insight_html += f"<li>{ip} — {cnt} times</li>"
        insight_html += "</ol>"

    # === Charts ===
    images = {}

    # Suspicious entries per file
    if file_summary:
        files, counts = zip(*file_summary)
        plt.figure(figsize=(6, 4))
        plt.barh(files, counts)
        plt.title("Suspicious Entries per File")
        plt.xlabel("Count")
        plt.tight_layout()
        chart1 = "suspicious_per_file.png"
        plt.savefig(chart1)
        plt.close()
        images["chart1"] = chart1
        insight_html += '<p><img src="cid:chart1"></p>'

    # Malicious vs Clean IPs
    if all_ips:
        clean_count = len(all_ips) - len(malicious_ips)
        plt.figure(figsize=(5, 5))
        plt.pie([len(malicious_ips), clean_count], labels=["Malicious", "Clean"], autopct='%1.1f%%')
        plt.title("Malicious vs Clean IPs")
        chart2 = "ip_distribution.png"
        plt.savefig(chart2)
        plt.close()
        images["chart2"] = chart2
        insight_html += '<p><img src="cid:chart2"></p>'

    # === Final Report ===
    if report_sections:
        final_report = f"""
        <html>
        <body>
        <h2>🚨 PCAP Threat Report</h2>
        {insight_html}
        <hr>
        {''.join(report_sections)}
        <hr>
        <p style="font-size:12px;color:gray;">Generated automatically by your Cyber Lab Script</p>
        </body>
        </html>
        """
        print("[!] Alerts detected. Sending detailed report...")
        send_email_alert("🚨 PCAP Threat Report", final_report, images)
    else:
        print("[+] No suspicious activity detected.")


if __name__ == "__main__":
    analyze_results()
