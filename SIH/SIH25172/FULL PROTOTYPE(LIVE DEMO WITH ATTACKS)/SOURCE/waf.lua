-- WAF Lua Module for OpenResty
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
    path = ngx.re.gsub(path, "/\\d+(?=/|$)", "/<ID>", "jo")

    -- Handle query parameters
    if string.find(path, "?") then
        local base_path, query = string.match(path, "([^?]+)\?(.+)")
        if query then
            -- Replace numeric values in query parameters
            query = ngx.re.gsub(query, "=\\d+", "=<ID>", "jog")
            -- Replace other parameter values
            query = ngx.re.gsub(query, "=([^&\\d][^&]*)", "=<VAL>", "jog")
            path = base_path .. "?" .. query
        end
    end

    -- Replace long alphanumeric strings with <TOKEN>
    path = ngx.re.gsub(path, "\\b[a-zA-Z0-9]{6,}\\b", "<TOKEN>", "jog")

    -- Replace remaining numbers
    path = ngx.re.gsub(path, "\\b\\d+\\b", "<NUM>", "jog")

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
    local log_entry = string.format('%s %s "%s" score=%.3f\n', 
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
