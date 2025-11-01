Domain Health Check

A simple Bash script that checks if domains resolve (DNS), respond to ping, and serve HTTP/HTTPS.
It runs checks in parallel and saves results to a reports/ folder.

🧩 Requirements

The script depends on curl, ping, and dig.

Install missing packages (Debian/Ubuntu)
sudo apt update
sudo apt install curl iputils-ping dnsutils

🚀 Quick Start
1. Download

domain_health_check.sh

domains.txt

2. Open a terminal in that folder
3. Make the script executable
chmod +x domain_health_check.sh

4. Run the script
./domain_health_check.sh domains.txt

5. View reports

Text reports are saved in the reports/ directory.

⚙️ Optional Flags
Flag	Description
-html	Generates an additional HTML report with collapsible sections for passed/failed domains.
-csv	Generates a CSV version of the report for use in spreadsheets.
Example
./domain_health_check.sh domains.txt -html -csv
