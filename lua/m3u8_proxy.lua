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
    -- Handle double-escaped slashes from client-side encoding
    str = str:gsub("\\/", "/")
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

-- Extract host and base URL from target
local target_host = decoded_url:match("https?://([^/]+)")

-- Get base directory for relative URL resolution (handles nested paths like /x36xhzz/url_2/)
local function get_base_directory(url)
    -- Remove filename, keep directory path
    local dir = url:match("^(.+/)")
    if dir then return dir end
    -- Fallback to domain root
    return url:match("^(https?://[^/]+/)") or url
end
local base_dir = get_base_directory(decoded_url)

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
local encoded_headers = ngx.escape_uri(cjson.encode(headers))

-- Get correct scheme (handle Koyeb/Cloudflare proxying via X-Forwarded-Proto)
local function get_scheme()
    local forwarded = ngx.var.http_x_forwarded_proto
    if forwarded and (forwarded == "https" or forwarded == "http") then
        return forwarded
    end
    return ngx.var.scheme or "https"
end

-- Helper: Convert relative URL to absolute (handles ./, ../, /path, nested dirs)
local function to_absolute_url(relative, base_directory)
    if not relative then return base_directory end
    
    -- Already absolute URL
    if relative:match("^https?://") then
        return relative
    end
    
    -- Absolute path from domain root (starts with /)
    if relative:match("^/") then
        local domain = base_directory:match("^(https?://[^/]+)")
        return domain .. relative
    end
    
    -- Relative path: resolve against base directory
    -- Remove leading ./ or ../ for clean concatenation
    local clean_relative = relative:gsub("^%.?/", "")
    return base_directory .. clean_relative
end

-- Helper: Build proxied URL for segments/playlists (matches your exact routes)
local function build_proxy_url(abs_url, proxy_type)
    local scheme = get_scheme()
    local host = ngx.var.http_host or ngx.var.server_name
    local extension = proxy_type == "ts-proxy" and ".ts" or ".m3u8"
    
    local encoded_url = ngx.escape_uri(abs_url)
    
    return scheme .. "://" .. host .. "/" .. proxy_type .. extension .. "?url=" .. encoded_url .. "&headers=" .. encoded_headers
end

-- Track what the next URL line should be
local next_is_segment = false

-- Process the M3U8 content line by line
local lines = {}
for line in content:gmatch("[^\r\n]+") do
    local processed_line = line

    if line ~= "" then
        -- URL line (not a tag) - this is where segments/playlists are listed
        if not line:match("^#") then
            local abs_url = to_absolute_url(line, base_dir)
            
            -- Determine proxy type: segment (.ts/.m4s) or playlist (.m3u8)
            local proxy_type
            if next_is_segment then
                proxy_type = "ts-proxy"
                next_is_segment = false
            elseif line:match("%.m3u8$") or line:match("%.m3u$") then
                proxy_type = "m3u8-proxy"
            elseif line:match("%.ts$") or line:match("%.m4s$") or line:match("%.aac$") or line:match("%.mp4$") or line:match("%.vtt$") then
                proxy_type = "ts-proxy"
            else
                -- Default to m3u8 for unknown (safer fallback)
                proxy_type = "m3u8-proxy"
            end
            
            -- Rewrite URL to point to our proxy
            processed_line = build_proxy_url(abs_url, proxy_type)

        -- #EXTINF = next line is a video segment
        elseif line:match("^#EXTINF") then
            next_is_segment = true

        -- #EXT-X-STREAM-INF = next line is a variant playlist
        elseif line:match("^#EXT%-X%-STREAM%-INF") then
            next_is_segment = false

        -- #EXT-X-KEY = encryption key (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-KEY") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local is_segment = uri:match("%.ts$") or uri:match("%.m4s$") or uri:match("%.aac$")
                local proxy_type = is_segment and "ts-proxy" or "m3u8-proxy"
                local proxied = build_proxy_url(abs_uri, proxy_type)
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- #EXT-X-SESSION-KEY (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-SESSION%-KEY") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "ts-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- #EXT-X-MAP = init segment (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-MAP") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "ts-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- #EXT-X-I-FRAME-STREAM-INF = i-frame playlist (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-I%-FRAME%-STREAM%-INF") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "m3u8-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- #EXT-X-MEDIA = alternate rendition (audio/subs) playlist (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-MEDIA") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "m3u8-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- LL-HLS: #EXT-X-PART = partial segment (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-PART:") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "ts-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- LL-HLS: #EXT-X-PRELOAD-HINT (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-PRELOAD%-HINT") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "ts-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- LL-HLS: #EXT-X-RENDITION-REPORT (rewrite URI= attribute)
        elseif line:match("^#EXT%-X%-RENDITION%-REPORT") then
            local uri = line:match('URI="([^"]+)"')
            if uri then
                local abs_uri = to_absolute_url(uri, base_dir)
                local proxied = build_proxy_url(abs_uri, "m3u8-proxy")
                processed_line = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
            end

        -- #EXT-X-BYTERANGE = next line is segment (byte range)
        elseif line:match("^#EXT%-X%-BYTERANGE") then
            next_is_segment = true
        end
    end

    table.insert(lines, processed_line)
end

local result = table.concat(lines, "\n")

-- Set response headers
ngx.header["Content-Type"] = "application/vnd.apple.mpegurl"
ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"

ngx.say(result)
