# 🌐 Domain Health Check

A simple Bash script that checks if domains:

- Resolve via DNS
- Respond to ping
- Serve HTTP/HTTPS

It runs checks in parallel and saves results to the `reports/` folder.

---

## 🧩 Requirements

This script depends on the following tools:

- `curl`
- `ping`
- `dig`

### Install on Debian/Ubuntu

```bash
sudo apt update
sudo apt install curl iputils-ping dnsutils

#### 🚀 Quick Start

Download the following files:

domain_health_check.sh

domains.txt

Open a terminal in that folder

Make the script executable:

chmod +x domain_health_check.sh

Run the script:

./domain_health_check.sh domains.txt

View reports:

Text reports are saved in the reports/ directory.

⚙️ Optional Flags

Flag

Description

-html

Generates an additional HTML report with collapsible sections for passed/failed domains

-csv

Generates a CSV version of the report for use in spreadsheets

Example Usage

./domain_health_check.sh domains.txt -html -csv