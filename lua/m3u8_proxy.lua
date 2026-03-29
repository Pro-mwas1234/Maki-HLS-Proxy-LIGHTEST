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

-- Safely parse headers JSON
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
local base_url = decoded_url:match("(.+//[^/]+/[^/]*/)") or decoded_url:match("(.+//[^/]+/)") or decoded_url

-- Browser-like headers (lowercase keys to avoid duplicates)
local user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
}
math.randomseed(ngx.now())
local selected_ua = user_agents[math.random(#user_agents)]

local req_headers = {
    ["host"] = target_host,
    ["user-agent"] = headers["user-agent"] or headers["User-Agent"] or selected_ua,
    ["accept"] = "*/*",
    ["accept-language"] = "en-US,en;q=0.9",
    ["accept-encoding"] = "gzip, deflate, br",
    ["connection"] = "keep-alive",
    ["sec-ch-ua"] = '"Not_A Brand";v="8", "Chromium";v="122", "Google Chrome";v="122"',
    ["sec-ch-ua-mobile"] = "?0",
    ["sec-ch-ua-platform"] = '"Windows"',
    ["sec-fetch-dest"] = "empty",
    ["sec-fetch-mode"] = "cors",
    ["sec-fetch-site"] = "cross-site",
    ["priority"] = "u=1, i",
}

-- Merge custom headers (normalize to lowercase)
for k, v in pairs(headers) do
    local key = k:lower()
    if key ~= "host" then
        req_headers[key] = v
    end
end
if not req_headers["referer"] and req_headers["origin"] then
    req_headers["referer"] = req_headers["origin"]
end

-- Fetch the M3U8 playlist
local res, err = httpc:request_uri(decoded_url, {
    method = "GET",
    headers = req_headers,
    ssl_verify = false,
})

if not res then
    ngx.log(ngx.ERR, "Failed to fetch M3U8: ", err)
    ngx.status = 502
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "connection_failed", "message": "Failed to fetch playlist"}')
    return ngx.exit(502)
end

-- Detect Cloudflare block
if res.status == 403 and res.body and type(res.body) == "string" and res.body:match("Cloudflare Ray ID") then
    ngx.status = 403
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "blocked_by_cloudflare", "message": "Origin is protected by Cloudflare"}')
    return ngx.exit(403)
end

if res.status ~= 200 then
    ngx.status = res.status
    ngx.header["Content-Type"] = "application/vnd.apple.mpegurl"
    ngx.say(res.body)
    return ngx.exit(res.status)
end

local content = res.body
local encoded_headers = ngx.escape_uri(cjson.encode(headers))
local proxy_host = ngx.var.scheme .. "://" .. ngx.var.http_host

-- Helper: Convert relative URL to absolute
local function to_absolute_url(relative, base)
    if relative:match("^https?://") then
        return relative  -- Already absolute
    end
    if relative:match("^/") then
        -- Absolute path: https://domain.com/path
        return base:match("^(https?://[^/]+)") .. relative
    end
    -- Relative path: append to base directory
    return base .. relative:gsub("^%.?/", "")
end

-- Helper: Build proxied URL for segments/playlists
local function build_proxy_url(abs_url, is_segment)
    local endpoint = is_segment and "ts-proxy.ts" or "m3u8-proxy.m3u8"
    return proxy_host .. "/" .. endpoint .. "?url=" .. ngx.escape_uri(abs_url) .. "&headers=" .. encoded_headers
end

-- Process M3U8 line by line
local lines = {}
local next_is_segment = false

for line in content:gmatch("[^\r\n]+") do
    local output = line
    
    -- Skip empty lines and comments
    if line ~= "" and not line:match("^#") then
        -- This is a URL line (segment or playlist)
        local abs_url = to_absolute_url(line, base_url)
        
        -- Determine if this is a video segment (.ts, .m4s, etc.) or a playlist
        local is_segment = line:match("%.ts$") or line:match("%.m4s$") or line:match("%.aac$") or 
                          line:match("%.mp4$") or line:match("%.vtt$") or next_is_segment
        
        -- Rewrite URL to point to our proxy
        output = build_proxy_url(abs_url, is_segment)
        next_is_segment = false
        
    -- Track tags that indicate next line is a segment
    elseif line:match("^#EXTINF") or line:match("^#EXT%-X%-BYTERANGE") then
        next_is_segment = true
        
    -- Rewrite URI= attributes in tags (keys, maps, etc.)
    elseif line:match("^#EXT%-X%-KEY") or line:match("^#EXT%-X%-MAP") or line:match("^#EXT%-X%-PART") then
        local uri = line:match('URI="([^"]+)"')
        if uri then
            local abs_uri = to_absolute_url(uri, base_url)
            local is_seg = uri:match("%.ts$") or uri:match("%.m4s$")
            local proxied = build_proxy_url(abs_uri, is_seg)
            output = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
        end
    end
    
    table.insert(lines, output)
end

-- Return the rewritten playlist
ngx.header["Content-Type"] = "application/vnd.apple.mpegurl"
ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
ngx.say(table.concat(lines, "\n"))
