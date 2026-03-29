local http = require "resty.http"
local cjson = require "cjson.safe"
local access = require "access"

-- Handle OPTIONS preflight
if ngx.req.get_method() == "OPTIONS" then
    return access.handle_options()
end

-- Check origin
if not access.check() then
    return access.deny()
end

-- Set CORS headers for response
access.set_cors_headers()

-- Get query parameters using built-in method
local args = ngx.req.get_uri_args()
local url = args.url

-- Built-in URL decode (no utils.lua dependency)
local function url_decode(str)
    if not str then return nil end
    str = str:gsub("+", " ")
    str = str:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    return str
end

local decoded_url = url_decode(url)

-- Safely parse headers JSON with robust error handling
local headers = {}
if args.headers then
    local decoded = url_decode(args.headers)
    if decoded then
        local parsed, err = cjson.decode(decoded)
        if parsed and type(parsed) == "table" then
            headers = parsed
        else
            ngx.log(ngx.ERR, "Failed to parse headers JSON: ", decoded, " | Error: ", err or "unknown")
            ngx.status = 400
            ngx.header["Content-Type"] = "application/json"
            ngx.say('{"error": "invalid_headers_format", "message": "Headers must be valid URL-encoded JSON object"}')
            return ngx.exit(400)
        end
    end
end

if not decoded_url then
    ngx.status = 400
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "missing_url_parameter", "message": "Missing required url parameter"}')
    return ngx.exit(400)
end

ngx.log(ngx.INFO, "Fetching M3U8: ", decoded_url)

-- Create HTTP client
local httpc = http.new()
httpc:set_timeout(15000)

-- Extract host from URL
local target_host = decoded_url:match("https?://([^/]+)")

-- Browser-like User-Agent pool (rotate randomly)
local user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
}
math.randomseed(ngx.now())
local selected_ua = user_agents[math.random(#user_agents)]

-- Chrome Client Hints pool (rotate to avoid fingerprinting)
local client_hints = {
    { ua = '"Not_A Brand";v="8", "Chromium";v="122", "Google Chrome";v="122"', platform = '"Windows"' },
    { ua = '"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"', platform = '"macOS"' },
    { ua = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"', platform = '"Linux"' },
}
local hints = client_hints[math.random(#client_hints)]

-- Build request headers with FULL browser mimicry (ALL LOWERCASE keys)
local req_headers = {
    -- Core headers
    ["host"] = target_host,
    ["user-agent"] = headers["user-agent"] or headers["User-Agent"] or selected_ua,
    ["accept"] = headers["accept"] or headers["Accept"] or "*/*",
    ["accept-language"] = headers["accept-language"] or headers["Accept-Language"] or "en-US,en;q=0.9",
    ["accept-encoding"] = headers["accept-encoding"] or headers["Accept-Encoding"] or "gzip, deflate, br",
    
    -- Connection headers (browser-like)
    ["connection"] = "keep-alive",
    ["upgrade-insecure-requests"] = "1",
    
    -- Chrome Client Hints (critical for modern bot detection)
    ["sec-ch-ua"] = headers["sec-ch-ua"] or headers["Sec-Ch-Ua"] or hints.ua,
    ["sec-ch-ua-mobile"] = headers["sec-ch-ua-mobile"] or headers["Sec-Ch-Ua-Mobile"] or "?0",
    ["sec-ch-ua-platform"] = headers["sec-ch-ua-platform"] or headers["Sec-Ch-Ua-Platform"] or hints.platform,
    
    -- Fetch metadata headers (browser security)
    ["sec-fetch-dest"] = headers["sec-fetch-dest"] or headers["Sec-Fetch-Dest"] or "empty",
    ["sec-fetch-mode"] = headers["sec-fetch-mode"] or headers["Sec-Fetch-Mode"] or "cors",
    ["sec-fetch-site"] = headers["sec-fetch-site"] or headers["Sec-Fetch-Site"] or "cross-site",
    ["sec-fetch-user"] = "?1",  -- Indicates user-initiated request
    
    -- Priority header (Chrome sends this)
    ["priority"] = "u=1, i",
}

-- Merge custom headers (NORMALIZE ALL KEYS TO LOWERCASE to prevent duplicates)
for k, v in pairs(headers) do
    local key_lower = k:lower()
    if key_lower ~= "host" then
        req_headers[key_lower] = v
    end
end

-- Auto-fill Referer from Origin if missing (many origins validate this)
if not req_headers["referer"] and req_headers["origin"] then
    req_headers["referer"] = req_headers["origin"]
end

-- Forward cookies if provided (for personal testing only)
if headers["cookie"] or headers["Cookie"] then
    req_headers["cookie"] = headers["cookie"] or headers["Cookie"]
end

-- Debug logging (uncomment for troubleshooting)
-- local debug_log = {}
-- for k, v in pairs(req_headers) do debug_log[k] = v end
-- ngx.log(ngx.INFO, "Outgoing headers: ", cjson.encode(debug_log))
-- ngx.log(ngx.INFO, "Target URL: ", decoded_url)

-- Add small random delay to mimic human timing (0-500ms)
local delay = math.random(0, 500) / 1000
ngx.sleep(delay)

-- Fetch the M3U8 playlist with retry logic
local max_retries = 2
local base_delay = 0.5
local res, err

for attempt = 1, max_retries + 1 do
    res, err = httpc:request_uri(decoded_url, {
        method = "GET",
        headers = req_headers,
        ssl_verify = false,
    })
    
    -- Success or client error (4xx) - don't retry
    if res and res.status < 500 then
        break
    end
    
    -- Server error (5xx) - retry with backoff
    if attempt <= max_retries then
        local backoff = base_delay * math.pow(2, attempt - 1)
        ngx.log(ngx.INFO, "Retry attempt ", attempt, " after ", backoff, "s due to error: ", err)
        ngx.sleep(backoff)
    end
end

-- Handle connection errors after all retries
if not res then
    ngx.log(ngx.ERR, "Failed to fetch M3U8 after retries: ", err)
    ngx.status = 502
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "connection_failed", "message": "Failed to fetch playlist: ' .. (err or "unknown") .. '"}')
    return ngx.exit(502)
end

-- Detect Cloudflare block page and return clean JSON error
if res.status == 403 and res.body and type(res.body) == "string" then
    if res.body:match("Cloudflare Ray ID") or res.body:match("Attention Required") or res.body:match("cf%-wrapper") then
        ngx.log(ngx.WARN, "Cloudflare block detected for URL: ", decoded_url)
        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say('{"error": "blocked_by_cloudflare", "message": "Origin server is protected by Cloudflare bot detection. This cannot be bypassed at the proxy level.", "ray_id": "' .. (res.headers["cf-ray"] or "unknown") .. '"}')
        return ngx.exit(403)
    end
end

-- Handle non-200 responses
if res.status ~= 200 then
    ngx.log(ngx.ERR, "M3U8 returned status: ", res.status)
    ngx.status = res.status
    ngx.header["Content-Type"] = "application/vnd.apple.mpegurl"
    ngx.say(res.body)
    return ngx.exit(res.status)
end

local content = res.body
local base_url = decoded_url:match("(.+//[^/]+)/") or decoded_url:match("(.+/.+/)")

-- Helper: rewrite URI attribute in a line
local function rewrite_uri_attr(line, proxy_type)
    local uri = line:match('URI="([^"]+)"')
    if uri then
        local abs_url = uri:match("^https?://") and uri or (base_url .. uri:gsub("^/", ""))
        local encoded_headers = ngx.escape_uri(cjson.encode(headers))
        local proxied = ngx.var.scheme .. "://" .. ngx.var.http_host .. "/" .. proxy_type .. ".ts?url=" .. ngx.escape_uri(abs_url) .. "&headers=" .. encoded_headers
        local escaped_proxied = proxied:gsub("%%", "%%%%")
        return line:gsub('URI="[^"]+"', 'URI="' .. escaped_proxied .. '"')
    end
    return line
end

-- Track what the next URL line should be
local next_line_type = nil

-- Process the M3U8 content line by line
local lines = {}
for line in content:gmatch("[^\r\n]+") do
    local processed_line = line

    if line ~= "" then
        -- URL line (not a tag)
        if not line:match("^#") then
            local abs_url = line:match("^https?://") and line or (base_url .. line:gsub("^/", ""))
            local proxy_type

            if next_line_type == "segment" then
                proxy_type = "ts-proxy"
            elseif next_line_type == "playlist" then
                proxy_type = "m3u8-proxy"
            else
                -- Fallback: guess based on extension
                if line:match("%.ts") or line:match("%.m4s") or line:match("%.aac") or line:match("%.mp4") or line:match("%.vtt") then
                    proxy_type = "ts-proxy"
                else
                    proxy_type = "m3u8-proxy"
                end
            end

            local encoded_headers = ngx.escape_uri(cjson.encode(headers))
            processed_line = ngx.var.scheme .. "://" .. ngx.var.http_host .. "/" .. proxy_type .. ".ts?url=" .. ngx.escape_uri(abs_url) .. "&headers=" .. encoded_headers
            next_line_type = nil

        -- #EXTINF = next line is a segment
        elseif line:match("^#EXTINF") then
            next_line_type = "segment"

        -- #EXT-X-STREAM-INF = next line is a variant playlist
        elseif line:match("^#EXT%-X%-STREAM%-INF") then
            next_line_type = "playlist"

        -- #EXT-X-KEY = encryption key
        elseif line:match("^#EXT%-X%-KEY") then
            processed_line = rewrite_uri_attr(line, "ts-proxy")

        -- #EXT-X-SESSION-KEY
        elseif line:match("^#EXT%-X%-SESSION%-KEY") then
            processed_line = rewrite_uri_attr(line, "ts-proxy")

        -- #EXT-X-MAP = init segment
        elseif line:match("^#EXT%-X%-MAP") then
            processed_line = rewrite_uri_attr(line, "ts-proxy")

        -- #EXT-X-I-FRAME-STREAM-INF = i-frame playlist
        elseif line:match("^#EXT%-X%-I%-FRAME%-STREAM%-INF") then
            processed_line = rewrite_uri_attr(line, "m3u8-proxy")

        -- #EXT-X-MEDIA = alternate rendition (audio/subs) playlist
        elseif line:match("^#EXT%-X%-MEDIA") then
            processed_line = rewrite_uri_attr(line, "m3u8-proxy")

        -- LL-HLS: #EXT-X-PART = partial segment
        elseif line:match("^#EXT%-X%-PART:") then
            processed_line = rewrite_uri_attr(line, "ts-proxy")

        -- LL-HLS: #EXT-X-PRELOAD-HINT
        elseif line:match("^#EXT%-X%-PRELOAD%-HINT") then
            processed_line = rewrite_uri_attr(line, "ts-proxy")

        -- LL-HLS: #EXT-X-RENDITION-REPORT
        elseif line:match("^#EXT%-X%-RENDITION%-REPORT") then
            processed_line = rewrite_uri_attr(line, "m3u8-proxy")

        -- #EXT-X-BYTERANGE = next line is segment (byte range)
        elseif line:match("^#EXT%-X%-BYTERANGE") then
            next_line_type = "segment"
        end
    end

    table.insert(lines, processed_line)
end

local result = table.concat(lines, "\n")

-- Set response headers
ngx.header["Content-Type"] = "application/vnd.apple.mpegurl"
ngx.header["Cache-Control"] = "no-cache"

ngx.say(result)
