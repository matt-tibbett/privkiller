# Domain Health Check

A small Bash script that checks if domains resolve, respond to ping, and serve HTTP.

## Requires curl, ping and dig

**Install missing packages on Debian/Ubuntu**
- sudo apt update
- sudo apt install curl
- sudo apt install iputils-ping
- sudo apt install dnsutils

### Quick Start

1. **Download**
   - `domain_health_check.sh`
   - `domains.txt`

2. **Open a terminal in that folder.**

3. **Make the script executable**
   - chmod +x domain_health_check.sh

4. **Run the script**
   - ./domain_health_check.sh domains.txt

5. **View reports**
   - reports/

6. **Optional html flag**
   - '-html'
   - Example './domain_health_check.sh domains.txt -html'
   provides a copy of the report in html.