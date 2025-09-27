# Create OpenResty/Nginx configuration (Day 4)
nginx_conf = '''# OpenResty Configuration for ML-powered WAF
worker_processes auto;
error_log /var/log/waf/error.log info;
pid /var/run/openresty.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    # Basic HTTP configuration
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    # Logging format
    log_format waf_format '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent" '
                         '$request_time $upstream_response_time '
                         '"$http_x_ml_sequence" "$http_x_anomaly_score"';
    
    access_log /var/log/waf/access.log waf_format;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # Lua configuration
    lua_package_path "/usr/local/openresty/site/lualib/?.lua;/usr/local/openresty/lualib/?.lua;;";
    lua_shared_dict waf_cache 10m;
    lua_shared_dict waf_stats 1m;
    
    # Initialize Lua modules
    init_by_lua_block {
        -- Initialize HTTP client and JSON library
        local http = require "resty.http"
        local cjson = require "cjson"
        
        -- Global configuration
        _G.ML_API_HOST = os.getenv("ML_API_HOST") or "ml-sidecar"
        _G.ML_API_PORT = os.getenv("ML_API_PORT") or "8080"
        _G.ML_API_TIMEOUT = tonumber(os.getenv("ML_API_TIMEOUT")) or 2000
        _G.DETECTION_LOG_PATH = os.getenv("DETECTION_LOG_PATH") or "/var/log/waf/detections.log"
        
        ngx.log(ngx.INFO, "WAF initialized with ML API at " .. _G.ML_API_HOST .. ":" .. _G.ML_API_PORT)
    }
    
    init_worker_by_lua_block {
        -- Initialize per-worker resources
        local stats = ngx.shared.waf_stats
        stats:set("requests_total", 0)
        stats:set("anomalies_detected", 0)
        stats:set("cache_hits", 0)
    }
    
    # Upstream configuration
    upstream backend {
        server sample-app:80;
        keepalive 32;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/s;
    
    server {
        listen 80 default_server;
        server_name _;
        
        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Referrer-Policy "strict-origin-when-cross-origin";
        
        # Health check endpoint
        location = /health {
            access_log off;
            return 200 "WAF Health OK\\n";
        }
        
        # WAF statistics endpoint
        location = /waf/stats {
            content_by_lua_block {
                local cjson = require "cjson"
                local stats = ngx.shared.waf_stats
                
                local data = {
                    requests_total = stats:get("requests_total") or 0,
                    anomalies_detected = stats:get("anomalies_detected") or 0,
                    cache_hits = stats:get("cache_hits") or 0,
                    uptime = ngx.time() - (stats:get("start_time") or ngx.time())
                }
                
                ngx.header.content_type = "application/json"
                ngx.say(cjson.encode(data))
            }
        }
        
        # Special handling for login endpoints
        location ~ ^/login|^/auth {
            limit_req zone=login burst=10 nodelay;
            
            access_by_lua_block {
                require("waf").process_request()
            }
            
            proxy_pass http://backend;
            include proxy_params;
        }
        
        # API endpoints with higher rate limits
        location /api/ {
            limit_req zone=api burst=50 nodelay;
            
            access_by_lua_block {
                require("waf").process_request()
            }
            
            proxy_pass http://backend;
            include proxy_params;
        }
        
        # All other requests
        location / {
            access_by_lua_block {
                require("waf").process_request()
            }
            
            proxy_pass http://backend;
            include proxy_params;
        }
    }
    
    # Proxy parameters
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 5s;
    proxy_send_timeout 10s;
    proxy_read_timeout 10s;
    proxy_buffering on;
    proxy_buffer_size 4k;
    proxy_buffers 8 4k;
}
'''

# Create proxy_params file
proxy_params = '''proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $server_name;
proxy_redirect off;
'''

# Create the WAF Lua module
waf_lua = '''-- WAF Lua Module for OpenResty
-- Handles ML-based anomaly detection with non-blocking inference

local _M = {}

local http = require "resty.http"
local cjson = require "cjson"

-- Configuration
local ML_API_URL = "http://" .. (_G.ML_API_HOST or "ml-sidecar") .. ":" .. (_G.ML_API_PORT or "8080") .. "/score"
local TIMEOUT = _G.ML_API_TIMEOUT or 2000
local LOG_FILE = _G.DETECTION_LOG_PATH or "/var/log/waf/detections.log"

-- Cache for recent results
local cache = ngx.shared.waf_cache
local stats = ngx.shared.waf_stats

-- Normalize request path (mirror Python normalization)
local function normalize_path(path)
    if not path then return "" end
    
    -- Replace numeric IDs with <ID>
    path = ngx.re.gsub(path, "/\\\\d+(?=/|$)", "/<ID>", "jo")
    
    -- Handle query parameters
    if string.find(path, "?") then
        local base_path, query = string.match(path, "([^?]+)\\?(.+)")
        if query then
            -- Replace numeric values in query parameters
            query = ngx.re.gsub(query, "=\\\\d+", "=<ID>", "jog")
            -- Replace other parameter values
            query = ngx.re.gsub(query, "=([^&\\\\d][^&]*)", "=<VAL>", "jog")
            path = base_path .. "?" .. query
        end
    end
    
    -- Replace long alphanumeric strings with <TOKEN>
    path = ngx.re.gsub(path, "\\\\b[a-zA-Z0-9]{6,}\\\\b", "<TOKEN>", "jog")
    
    -- Replace remaining numbers
    path = ngx.re.gsub(path, "\\\\b\\\\d+\\\\b", "<NUM>", "jog")
    
    return path
end

-- Create HTTP sequence for ML analysis
local function create_sequence()
    local method = ngx.var.request_method
    local uri = ngx.var.request_uri or ngx.var.uri
    local normalized_path = normalize_path(uri)
    
    return method .. " " .. normalized_path
end

-- Log detection to file
local function log_detection(sequence, score, client_ip)
    local timestamp = ngx.localtime()
    local log_entry = string.format('%s %s "%s" score=%.3f\\n', 
                                  timestamp, client_ip, sequence, score)
    
    -- Async file writing
    local file = io.open(LOG_FILE, "a+")
    if file then
        file:write(log_entry)
        file:close()
    end
end

-- Call ML API asynchronously
local function call_ml_api_async(sequence, client_ip)
    local httpc = http.new()
    httpc:set_timeout(TIMEOUT)
    
    local request_body = cjson.encode({ seq = sequence })
    
    local res, err = httpc:request_uri(ML_API_URL, {
        method = "POST",
        body = request_body,
        headers = {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = "OpenResty-WAF/1.0"
        }
    })
    
    if res and res.status == 200 then
        local success, result = pcall(cjson.decode, res.body)
        if success and result then
            local score = result.score or 0.0
            local is_anomaly = result.anomalous or false
            
            -- Cache result for 60 seconds
            local cache_key = "seq:" .. sequence
            cache:set(cache_key, cjson.encode({
                score = score,
                anomalous = is_anomaly,
                timestamp = ngx.time()
            }), 60)
            
            -- Update statistics
            stats:incr("requests_total", 1)
            
            if is_anomaly then
                stats:incr("anomalies_detected", 1)
                log_detection(sequence, score, client_ip)
                
                ngx.log(ngx.WARN, "Anomaly detected: ", sequence, " score=", score, " ip=", client_ip)
            end
            
            -- Set response headers for debugging
            ngx.header["X-ML-Score"] = string.format("%.3f", score)
            ngx.header["X-ML-Anomaly"] = is_anomaly and "true" or "false"
            
        else
            ngx.log(ngx.ERR, "Failed to parse ML API response: ", err or "unknown error")
        end
    else
        ngx.log(ngx.ERR, "ML API call failed: ", err or "unknown error", " status=", res and res.status or "nil")
    end
    
    httpc:close()
end

-- Main processing function
function _M.process_request()
    -- Create normalized sequence
    local sequence = create_sequence()
    local client_ip = ngx.var.remote_addr
    
    -- Set header for logging
    ngx.req.set_header("X-ML-Sequence", sequence)
    
    -- Check cache first
    local cache_key = "seq:" .. sequence
    local cached_result = cache:get(cache_key)
    
    if cached_result then
        -- Cache hit
        stats:incr("cache_hits", 1)
        
        local success, result = pcall(cjson.decode, cached_result)
        if success and result then
            ngx.header["X-ML-Score"] = string.format("%.3f", result.score or 0.0)
            ngx.header["X-ML-Anomaly"] = result.anomalous and "true" or "false"
            ngx.header["X-Cache"] = "HIT"
            
            -- If cached result shows anomaly, log it again for recent activity
            if result.anomalous then
                ngx.log(ngx.WARN, "Cached anomaly: ", sequence, " score=", result.score, " ip=", client_ip)
            end
        end
    else
        -- Cache miss - make async API call
        ngx.header["X-Cache"] = "MISS"
        
        -- Non-blocking timer for ML API call
        local ok, err = ngx.timer.at(0, function(premature)
            if premature then return end
            call_ml_api_async(sequence, client_ip)
        end)
        
        if not ok then
            ngx.log(ngx.ERR, "Failed to create timer for ML API call: ", err)
        end
    end
    
    -- Request continues immediately (non-blocking)
    return
end

-- Optional: Block function for high-risk requests
function _M.should_block_request()
    -- This could implement immediate blocking for very high-risk patterns
    -- without waiting for ML API response
    
    local uri = ngx.var.request_uri or ""
    local method = ngx.var.request_method or ""
    
    -- Immediate blocking rules for obvious attacks
    local dangerous_patterns = {
        "%.%.%/",           -- Directory traversal
        "union%s+select",   -- SQL injection
        "<script",          -- XSS
        "javascript:",      -- XSS
        "/etc/passwd",      -- File access
        "cmd%.exe",         -- Command execution
    }
    
    local uri_lower = string.lower(uri)
    for _, pattern in ipairs(dangerous_patterns) do
        if string.find(uri_lower, pattern) then
            ngx.log(ngx.WARN, "Immediate block: dangerous pattern detected in ", uri)
            return true
        end
    end
    
    return false
end

return _M
'''

# Write configuration files
os.makedirs("webapp-ml-waf/config", exist_ok=True)

with open("webapp-ml-waf/config/nginx.conf", "w") as f:
    f.write(nginx_conf)

with open("webapp-ml-waf/config/proxy_params", "w") as f:
    f.write(proxy_params)

with open("webapp-ml-waf/config/waf.lua", "w") as f:
    f.write(waf_lua)

print("✅ Created OpenResty/Nginx configuration and Lua WAF module")