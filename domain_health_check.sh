#!/bin/bash
# ==============================================================
# DOMAIN HEALTH CHECK SCRIPT (Parallel + Colored Output + HTML + CSV)
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
  echo "Usage: $0 domain_list.txt [-html] [-csv]"
  exit 1
fi

domain_file="$1"
html_flag=false
csv_flag=false
[[ "$2" == "-html" || "$3" == "-html" ]] && html_flag=true
[[ "$2" == "-csv" || "$3" == "-csv" ]] && csv_flag=true
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
html_file="${report_dir}/domain_health_report_${timestamp}.html"
csv_file="${report_dir}/domain_health_report_${timestamp}.csv"
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
$($html_flag && echo -e "HTML Report: ${YELLOW}$html_file${RESET}")
$($csv_flag && echo -e "CSV Report: ${YELLOW}$csv_file${RESET}")
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
passed_html=""
failed_html=""
csv_data="Domain,DNS Status,Ping Status,HTTP Status,Resolved IP,Latency,HTTP Code,Redirect Target,SSL (HSTS)\n"

shopt -s nullglob
tmpfiles=( "$tmp_dir"/*.tmp )
for f in "${tmpfiles[@]}"; do
  content=$(<"$f")
  domain=$(grep -Eo "^\[.*\]" "$f" | tr -d '[]')
  dns_ok=false; ping_ok=false; http_ok=false

  [[ "$content" =~ "DNS Status:        OK" ]] && { ((dns_resolved_count++)); dns_ok=true; }
  [[ "$content" =~ "Ping Status:       OK" ]] && { ((reachable_count++)); ping_ok=true; }
  [[ "$content" =~ "HTTP Status:       OK" ]] && { ((http_ok_count++)); http_ok=true; }

  ip=$(grep "Resolved IP:" "$f" | awk -F': +' '{print $2}')
  latency=$(grep "Latency:" "$f" | awk -F': +' '{print $2}')
  code=$(grep "HTTP Code:" "$f" | awk -F': +' '{print $2}')
  redirect=$(grep "Redirect Target:" "$f" | awk -F': +' '{print $2}')
  ssl=$(grep "SSL (HSTS):" "$f" | awk -F': +' '{print $2}')
  dns_status=$(grep "DNS Status:" "$f" | awk -F': +' '{print $2}')
  ping_status=$(grep "Ping Status:" "$f" | awk -F': +' '{print $2}')
  http_status=$(grep "HTTP Status:" "$f" | awk -F': +' '{print $2}')

  row_html="<tr><td>$domain</td><td>$ip</td><td>$latency</td><td>$code</td><td>$redirect</td><td>$ssl</td></tr>"
  row_csv="\"$domain\",\"$dns_status\",\"$ping_status\",\"$http_status\",\"$ip\",\"$latency\",\"$code\",\"$redirect\",\"$ssl\""

  csv_data+="$row_csv\n"

  if $dns_ok && $ping_ok && $http_ok; then
    passed_html+="$row_html"
  else
    failed_html+="$row_html"
  fi
done
shopt -u nullglob

# --- Build final text report ---
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

# --- Build optional HTML report ---
if $html_flag; then
  pass_count=$http_ok_count
  fail_count=$(( total - pass_count ))
  success_rate=$(( total > 0 ? (pass_count * 100 / total) : 0 ))

  {
    echo "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Domain Health Report</title>"
    echo "<style>body{font-family:Arial,sans-serif;background:#fafafa;color:#333;padding:20px;}h1{color:#444;}details{margin-bottom:20px;}summary{font-size:1.2em;cursor:pointer;margin-top:10px;}table{border-collapse:collapse;width:100%;margin:10px 0;}th,td{border:1px solid #ccc;padding:8px;text-align:left;}th{background:#eee;}</style>"
    echo "</head><body><h1>Domain Health Report</h1>"
    echo "<p><strong>Date:</strong> $(date)</p>"
    echo "<p><strong>Total Domains:</strong> $total<br>"
    echo "<strong>Passed:</strong> $pass_count<br>"
    echo "<strong>Failed:</strong> $fail_count<br>"
    echo "<strong>Success Rate:</strong> ${success_rate}%</p><hr>"
    echo "<details open><summary>✅ Passed Domains ($pass_count)</summary>"
    echo "<table><tr><th>Domain</th><th>IP</th><th>Latency</th><th>HTTP Code</th><th>Redirect</th><th>SSL</th></tr>$passed_html</table></details>"
    echo "<details><summary>❌ Failed Domains ($fail_count)</summary>"
    echo "<table><tr><th>Domain</th><th>IP</th><th>Latency</th><th>HTTP Code</th><th>Redirect</th><th>SSL</th></tr>$failed_html</table></details>"
    echo "</body></html>"
  } > "$html_file"
fi

# --- Build optional CSV report ---
if $csv_flag; then
  echo -e "$csv_data" > "$csv_file"
fi

rm -rf "$tmp_dir"

echo -e "\n${GREEN}✅ Health check complete!${RESET}"
echo -e "Report saved to: ${YELLOW}$report_file${RESET}"

if $html_flag; then
  echo -e "HTML report: ${YELLOW}$html_file${RESET}"
fi

if $csv_flag; then
  echo -e "CSV report: ${YELLOW}$csv_file${RESET}"
fi

echo -e "${BLUE}==============================================================${RESET}"
