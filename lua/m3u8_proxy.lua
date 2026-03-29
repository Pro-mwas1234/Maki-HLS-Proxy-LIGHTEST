local http = require "resty.http"
local utils = require "utils"
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

-- Get query parameters
local args = utils.parse_query_params()
local url = utils.url_decode(args.url)

-- Safely parse headers JSON with error handling
local headers = {}
if args.headers then
    local decoded = utils.url_decode(args.headers)
    local ok, parsed = cjson.decode(decoded)
    if ok and parsed and type(parsed) == "table" then
        headers = parsed
    else
        ngx.log(ngx.ERR, "Failed to parse headers JSON: ", decoded)
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say('{"error": "invalid_headers_format", "message": "Headers must be valid URL-encoded JSON object"}')
        return ngx.exit(400)
    end
end

if not url then
    ngx.status = 400
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "missing_url_parameter", "message": "Missing required url parameter"}')
    return ngx.exit(400)
end

ngx.log(ngx.INFO, "Fetching M3U8: ", url)

-- Create HTTP client
local httpc = http.new()
httpc:set_timeout(15000)

-- Extract host from URL
local target_host = url:match("https?://([^/]+)")

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

-- Build request headers with FULL browser mimicry (ALL LOWERCASE keys)
local req_headers = {
    -- Core headers
    ["host"] = target_host,
    ["user-agent"] = headers["user-agent"] or headers["User-Agent"] or selected_ua,
    ["accept"] = headers["accept"] or headers["Accept"] or "*/*",
    ["accept-language"] = headers["accept-language"] or headers["Accept-Language"] or "en-US,en;q=0.9",
    ["accept-encoding"] = headers["accept-encoding"] or headers["Accept-Encoding"] or "gzip, deflate, br",
    
    -- Connection headers
    ["connection"] = "keep-alive",
    ["upgrade-insecure-requests"] = "1",
    
    -- Chrome Client Hints (critical for modern bot detection)
    ["sec-ch-ua"] = headers["sec-ch-ua"] or headers["Sec-Ch-Ua"] or '"Not_A Brand";v="8", "Chromium";v="122", "Google Chrome";v="122"',
    ["sec-ch-ua-mobile"] = headers["sec-ch-ua-mobile"] or headers["Sec-Ch-Ua-Mobile"] or "?0",
    ["sec-ch-ua-platform"] = headers["sec-ch-ua-platform"] or headers["Sec-Ch-Ua-Platform"] or '"Windows"',
    
    -- Fetch metadata headers
    ["sec-fetch-dest"] = headers["sec-fetch-dest"] or headers["Sec-Fetch-Dest"] or "empty",
    ["sec-fetch-mode"] = headers["sec-fetch-mode"] or headers["Sec-Fetch-Mode"] or "cors",
    ["sec-fetch-site"] = headers["sec-fetch-site"] or headers["Sec-Fetch-Site"] or "cross-site",
    ["sec-fetch-user"] = "?1",
    
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

-- Auto-fill Referer from Origin if missing
if not req_headers["referer"] and req_headers["origin"] then
    req_headers["referer"] = req_headers["origin"]
end

-- Debug logging (uncomment for troubleshooting)
-- local debug_log = {}
-- for k, v in pairs(req_headers) do debug_log[k] = v end
-- ngx.log(ngx.INFO, "Outgoing headers: ", cjson.encode(debug_log))
-- ngx.log(ngx.INFO, "Target URL: ", url)

-- Fetch the M3U8 playlist
local res, err = httpc:request_uri(url, {
    method = "GET",
    headers = req_headers,
    ssl_verify = false,
})

-- Handle connection errors
if not res then
    ngx.log(ngx.ERR, "Failed to fetch M3U8: ", err)
    ngx.status = 502
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "connection_failed", "message": "Failed to fetch playlist: ' .. (err or "unknown") .. '"}')
    return ngx.exit(502)
end

-- Detect Cloudflare block page and return clean JSON error
if res.status == 403 and res.body and type(res.body) == "string" and res.body:match("Cloudflare Ray ID") then
    ngx.log(ngx.WARN, "Cloudflare block detected for URL: ", url)
    ngx.status = 403
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "blocked_by_cloudflare", "message": "Origin server is protected by Cloudflare bot detection", "ray_id": "' .. (res.headers["cf-ray"] or "unknown") .. '"}')
    return ngx.exit(403)
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
local base_url = utils.get_base_url(url)

-- Helper: rewrite URI attribute in a line
local function rewrite_uri_attr(line, proxy_type)
    local uri = line:match('URI="([^"]+)"')
    if uri then
        local abs_url = utils.resolve_url(base_url, uri)
        local proxied = utils.build_proxy_url(abs_url, headers, proxy_type)
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
            local abs_url = utils.resolve_url(base_url, line)
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

            processed_line = utils.build_proxy_url(abs_url, headers, proxy_type)
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
