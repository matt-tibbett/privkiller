#!/usr/bin/env python3
# ==============================================================
# DOMAIN HEALTH CHECK SCRIPT (Parallel + Colored Output + HTML + CSV)
# --------------------------------------------------------------
# Checks each domain for DNS, Ping, and HTTP(S) availability.
# Runs in parallel using ThreadPoolExecutor. Saves reports to ./reports.
# ==============================================================

import os
import sys
import csv
import socket
import subprocess
import concurrent.futures
import datetime
import requests
from pathlib import Path

# --- Color Codes ---
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"

# --- Usage ---
if len(sys.argv) < 2:
    print("Usage: python3 domain_health_check.py domain_list.txt [-html] [-csv]")
    sys.exit(1)

domain_file = sys.argv[1]
html_flag = "-html" in sys.argv
csv_flag = "-csv" in sys.argv
parallel_jobs = 5  # default concurrency

if not os.path.isfile(domain_file):
    print(f"{RED}Error:{RESET} File '{domain_file}' not found.")
    sys.exit(1)

# --- Setup report paths ---
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_dir = Path("reports")
report_dir.mkdir(exist_ok=True)
report_file = report_dir / f"domain_health_report_{timestamp}.txt"
html_file = report_dir / f"domain_health_report_{timestamp}.html"
csv_file = report_dir / f"domain_health_report_{timestamp}.csv"

# --- Read and deduplicate domains ---
with open(domain_file, "r") as f:
    domains = sorted(set(line.strip() for line in f if line.strip() and not line.startswith("#")))

total = len(domains)

print(f"{BLUE}=============================================================={RESET}")
print(f"{BLUE}           DOMAIN HEALTH CHECK (Parallel + Colored){RESET}")
print(f"{BLUE}=============================================================={RESET}")
print(f"Date: {datetime.datetime.now()}")
print(f"Input File: {domain_file}")
print(f"Domains to Check: {YELLOW}{total}{RESET}")
print(f"Parallel Jobs: {YELLOW}{parallel_jobs}{RESET}")
print(f"Report File: {YELLOW}{report_file}{RESET}")
if html_flag:
    print(f"HTML Report: {YELLOW}{html_file}{RESET}")
if csv_flag:
    print(f"CSV Report: {YELLOW}{csv_file}{RESET}")
print(f"{BLUE}=============================================================={RESET}\n")

# --- Domain worker ---
def check_domain(domain):
    result = {
        "domain": domain,
        "dns_status": "FAIL",
        "ip_address": "N/A",
        "ping_status": "FAIL",
        "latency": "N/A",
        "http_status": "FAIL",
        "http_code": "N/A",
        "redirect": "N/A",
        "ssl": "Not detected",
    }

    # DNS Check
    try:
        ip = socket.gethostbyname(domain)
        result["ip_address"] = ip
        result["dns_status"] = "OK"
    except Exception:
        pass

    # Ping Check
    try:
        ping_cmd = ["ping", "-c", "1", "-W", "2", domain]
        output = subprocess.run(ping_cmd, capture_output=True, text=True)
        if output.returncode == 0:
            result["ping_status"] = "OK"
            for line in output.stdout.splitlines():
                if "time=" in line:
                    result["latency"] = line.split("time=")[-1].split(" ")[0] + " ms"
                    break
    except Exception:
        pass

    # HTTP/HTTPS Check
    try:
        resp = requests.head(f"http://{domain}", timeout=5, allow_redirects=True)
        result["http_code"] = resp.status_code
        if 200 <= resp.status_code < 400:
            result["http_status"] = "OK"
        if "Location" in resp.headers:
            result["redirect"] = resp.headers["Location"]
        if "Strict-Transport-Security" in resp.headers:
            result["ssl"] = "Enabled"
    except Exception:
        pass

    dns_color = GREEN if result["dns_status"] == "OK" else RED
    ping_color = GREEN if result["ping_status"] == "OK" else RED
    http_color = GREEN if result["http_status"] == "OK" else RED
    print(f"[{YELLOW}{domain}{RESET}] → DNS:{dns_color}{result['dns_status']}{RESET}, "
          f"Ping:{ping_color}{result['ping_status']}{RESET}, "
          f"HTTP:{http_color}{result['http_status']}{RESET}")

    return result


# --- Run checks in parallel ---
results = []
if total > 0:
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
        results = list(executor.map(check_domain, domains))
else:
    print(f"{RED}No domains found to check.{RESET}")
    sys.exit(0)

# --- Summarize ---
dns_resolved_count = sum(1 for r in results if r["dns_status"] == "OK")
reachable_count = sum(1 for r in results if r["ping_status"] == "OK")
http_ok_count = sum(1 for r in results if r["http_status"] == "OK")

# --- Write text report ---
with open(report_file, "w") as f:
    f.write("==============================================================\n")
    f.write("           DOMAIN HEALTH CHECK REPORT\n")
    f.write("==============================================================\n")
    f.write(f"Date: {datetime.datetime.now()}\n")
    f.write(f"Input File: {domain_file}\n")
    f.write(f"Domains Checked: {total}\n")
    f.write(f"Parallel Jobs: {parallel_jobs}\n")
    f.write("==============================================================\n\n")
    f.write("SUMMARY\n--------------------------------------------------------------\n")
    f.write(f"Total Domains Checked: {total}\n")
    f.write(f"DNS Resolved:          {dns_resolved_count} / {total}\n")
    f.write(f"Ping Reachable:        {reachable_count} / {total}\n")
    f.write(f"HTTP/HTTPS OK:         {http_ok_count} / {total}\n")
    f.write("--------------------------------------------------------------\n\n")
    f.write("DETAILED RESULTS\n--------------------------------------------------------------\n")
    for r in results:
        f.write(f"\n[{r['domain']}]\n")
        f.write("--------------------------------------------------------------\n")
        f.write(f"DNS Status:        {r['dns_status']}\n")
        f.write(f"Resolved IP:       {r['ip_address']}\n")
        f.write(f"Ping Status:       {r['ping_status']}\n")
        f.write(f"Latency:           {r['latency']}\n")
        f.write(f"HTTP Status:       {r['http_status']}\n")
        f.write(f"HTTP Code:         {r['http_code']}\n")
        f.write(f"Redirect Target:   {r['redirect']}\n")
        f.write(f"SSL (HSTS):        {r['ssl']}\n")
        f.write("--------------------------------------------------------------\n")

# --- HTML report ---
if html_flag:
    pass_count = http_ok_count
    fail_count = total - pass_count
    success_rate = int((pass_count * 100 / total) if total else 0)

    passed_html = ""
    failed_html = ""

    for r in results:
        row = f"<tr><td>{r['domain']}</td><td>{r['ip_address']}</td><td>{r['latency']}</td><td>{r['http_code']}</td><td>{r['redirect']}</td><td>{r['ssl']}</td></tr>"
        if r["dns_status"] == "OK" and r["ping_status"] == "OK" and r["http_status"] == "OK":
            passed_html += row
        else:
            failed_html += row

    with open(html_file, "w") as f:
        f.write(f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>Domain Health Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#fafafa;color:#333;padding:20px;}}
h1{{color:#444;}}
details{{margin-bottom:20px;}}
summary{{font-size:1.2em;cursor:pointer;margin-top:10px;}}
table{{border-collapse:collapse;width:100%;margin:10px 0;}}
th,td{{border:1px solid #ccc;padding:8px;text-align:left;}}
th{{background:#eee;}}
</style></head><body>
<h1>Domain Health Report</h1>
<p><strong>Date:</strong> {datetime.datetime.now()}</p>
<p><strong>Total Domains:</strong> {total}<br>
<strong>Passed:</strong> {pass_count}<br>
<strong>Failed:</strong> {fail_count}<br>
<strong>Success Rate:</strong> {success_rate}%</p><hr>
<details open><summary>✅ Passed Domains ({pass_count})</summary>
<table><tr><th>Domain</th><th>IP</th><th>Latency</th><th>HTTP Code</th><th>Redirect</th><th>SSL</th></tr>{passed_html}</table></details>
<details><summary>❌ Failed Domains ({fail_count})</summary>
<table><tr><th>Domain</th><th>IP</th><th>Latency</th><th>HTTP Code</th><th>Redirect</th><th>SSL</th></tr>{failed_html}</table></details>
</body></html>""")

# --- CSV report ---
if csv_flag:
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "DNS Status", "Ping Status", "HTTP Status", "Resolved IP", "Latency", "HTTP Code", "Redirect Target", "SSL (HSTS)"])
        for r in results:
            writer.writerow([
                r["domain"], r["dns_status"], r["ping_status"], r["http_status"],
                r["ip_address"], r["latency"], r["http_code"], r["redirect"], r["ssl"]
            ])

# --- Done ---
print(f"\n{GREEN}✅ Health check complete!{RESET}")
print(f"Report saved to: {YELLOW}{report_file}{RESET}")
if html_flag:
    print(f"HTML report: {YELLOW}{html_file}{RESET}")
if csv_flag:
    print(f"CSV report: {YELLOW}{csv_file}{RESET}")
print(f"{BLUE}=============================================================={RESET}")
