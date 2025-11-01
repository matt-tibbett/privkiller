#!/bin/bash
# ==============================================================
# DOMAIN HEALTH CHECK SCRIPT (Parallel + Colored Output)
# --------------------------------------------------------------
# Checks each domain for DNS, Ping, and HTTP(S) availability.
# Runs in parallel using xargs.  Saves reports to ./reports.
# ==============================================================

# --- Color Codes ---
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# --- Usage ---
if [ -z "$1" ]; then
  echo "Usage: $0 domain_list.txt"
  exit 1
fi

domain_file="$1"
parallel_jobs=5   # default concurrency

if [ ! -f "$domain_file" ]; then
  echo -e "${RED}Error:${RESET} File '$domain_file' not found."
  exit 1
fi

# --- Setup report paths ---
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
report_dir="reports"
mkdir -p "$report_dir"
report_file="${report_dir}/domain_health_report_${timestamp}.txt"
tmp_dir=$(mktemp -d)

# --- Read and deduplicate domains (safe everywhere) ---
domains=()
while IFS= read -r line; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  domains+=("$line")
done < "$domain_file"

# remove duplicates
IFS=$'\n' read -r -d '' -a domains < <(printf "%s\n" "${domains[@]}" | sort -u && printf '\0')
total=${#domains[@]}

echo -e "${BLUE}==============================================================${RESET}"
echo -e "${BLUE}           DOMAIN HEALTH CHECK (Parallel + Colored)${RESET}"
echo -e "${BLUE}==============================================================${RESET}"
echo -e "Date: $(date)"
echo -e "Input File: $domain_file"
echo -e "Domains to Check: ${YELLOW}$total${RESET}"
echo -e "Parallel Jobs: ${YELLOW}$parallel_jobs${RESET}"
echo -e "Report File: ${YELLOW}$report_file${RESET}"
echo -e "${BLUE}==============================================================${RESET}\n"

# --- Create worker script for xargs ---
worker="$tmp_dir/worker.sh"
cat > "$worker" <<'EOF'
#!/bin/bash
domain="$1"
tmpfile="$2"

dns_status="FAIL"
ip_address="N/A"
ping_status="FAIL"
latency="N/A"
http_status="FAIL"
http_code="N/A"
redirect_info="N/A"
ssl_info="N/A"

# --- DIG (DNS) ---
ip_address=$(dig +short "$domain" | head -n 1)
[ -n "$ip_address" ] && dns_status="OK"

# --- PING ---
if ping -c 1 -W 2 "$domain" &>/dev/null; then
  ping_status="OK"
  latency=$(ping -c 1 -W 2 "$domain" 2>/dev/null | awk -F'time=' '/time=/{print $2}' | awk '{print $1 " ms"}')
fi

# --- CURL (HTTP/HTTPS) ---
http_output=$(curl -Is --max-time 5 -L "$domain" 2>/dev/null)
http_code=$(echo "$http_output" | grep -m1 HTTP | tail -n1 | awk '{print $2}')
if [[ "$http_code" =~ ^2|3[0-9]{2}$ ]]; then
  http_status="OK"
fi
redirect_info=$(echo "$http_output" | grep -i "location:" | awk '{print $2}' | tr -d '\r')
ssl_info=$(echo "$http_output" | grep -i "strict-transport-security" >/dev/null && echo "Enabled" || echo "Not detected")

# --- Live feedback ---
dns_color=$([ "$dns_status" = "OK" ] && echo "\e[32m" || echo "\e[31m")
ping_color=$([ "$ping_status" = "OK" ] && echo "\e[32m" || echo "\e[31m")
http_color=$([ "$http_status" = "OK" ] && echo "\e[32m" || echo "\e[31m")
echo -e "[\e[33m$domain\e[0m] → DNS:${dns_color}$dns_status\e[0m, Ping:${ping_color}$ping_status\e[0m, HTTP:${http_color}$http_status\e[0m"

# --- Write detailed result ---
{
  echo
  echo "[$domain]"
  echo "--------------------------------------------------------------"
  echo "DNS Status:        $dns_status"
  echo "Resolved IP:       $ip_address"
  echo "Ping Status:       $ping_status"
  echo "Latency:           $latency"
  echo "HTTP Status:       $http_status"
  echo "HTTP Code:         $http_code"
  echo "Redirect Target:   ${redirect_info:-N/A}"
  echo "SSL (HSTS):        $ssl_info"
  echo "--------------------------------------------------------------"
} > "$tmpfile"
EOF
chmod +x "$worker"

# --- Run checks in parallel ---
if [ "$total" -gt 0 ]; then
  printf "%s\n" "${domains[@]}" | xargs -P "$parallel_jobs" -I{} "$worker" "{}" "$tmp_dir/{}.tmp"
else
  echo -e "${RED}No domains found to check.${RESET}"
fi

# --- Summarize results ---
dns_resolved_count=0
reachable_count=0
http_ok_count=0

shopt -s nullglob
tmpfiles=( "$tmp_dir"/*.tmp )
for f in "${tmpfiles[@]}"; do
  content=$(<"$f")
  [[ "$content" =~ "DNS Status:        OK" ]] && ((dns_resolved_count++))
  [[ "$content" =~ "Ping Status:       OK" ]] && ((reachable_count++))
  [[ "$content" =~ "HTTP Status:       OK" ]] && ((http_ok_count++))
done
shopt -u nullglob

# --- Build final report ---
{
  echo "=============================================================="
  echo "           DOMAIN HEALTH CHECK REPORT"
  echo "=============================================================="
  echo "Date: $(date)"
  echo "Input File: $domain_file"
  echo "Domains Checked: $total"
  echo "Parallel Jobs: $parallel_jobs"
  echo "=============================================================="
  echo
  echo "SUMMARY"
  echo "--------------------------------------------------------------"
  echo "Total Domains Checked: $total"
  echo "DNS Resolved:          $dns_resolved_count / $total"
  echo "Ping Reachable:        $reachable_count / $total"
  echo "HTTP/HTTPS OK:         $http_ok_count / $total"
  echo "--------------------------------------------------------------"
  echo
  echo "DETAILED RESULTS"
  echo "--------------------------------------------------------------"
} > "$report_file"

if [ ${#tmpfiles[@]} -gt 0 ]; then
  cat "${tmpfiles[@]}" >> "$report_file"
else
  echo "No results produced — check network tools or domain list." >> "$report_file"
fi

rm -rf "$tmp_dir"

echo -e "\n${GREEN}✅ Health check complete!${RESET}"
echo -e "Report saved to: ${YELLOW}$report_file${RESET}"
echo -e "${BLUE}==============================================================${RESET}"
