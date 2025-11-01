# Domain Health Check

A simple **Bash script** that checks if domains resolve (DNS), respond to ping, and serve HTTP/HTTPS.  
It runs checks in parallel and saves results to a `reports/` folder.

---

## 🧩 Requirements

The script depends on `curl`, `ping`, and `dig`.

### Install missing packages (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install curl iputils-ping dnsutils
🚀 Quick Start
Download

domain_health_check.sh

domains.txt

Open a terminal in that folder.

Make the script executable

bash
Copy code
chmod +x domain_health_check.sh
Run the script

bash
Copy code
./domain_health_check.sh domains.txt
View reports

Text reports are saved in the reports/ directory.

⚙️ Optional Flags
Flag	Description
-html	Generates an additional HTML report with collapsible sections for passed/failed domains.
-csv	Generates a CSV version of the report for use in spreadsheets.

Example:
bash
Copy code
./domain_health_check.sh domains.txt -html -csv
   