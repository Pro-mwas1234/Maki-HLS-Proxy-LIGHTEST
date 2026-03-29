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

-- Get query parameters
local args = ngx.req.get_uri_args()
local url = args.url

-- URL decode helper
local function url_decode(str)
    if not str then return nil end
    str = str:gsub("+", " ")
    str = str:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    return str
end

local decoded_url = url_decode(url)

-- Parse headers JSON
local headers = {}
if args.headers then
    local decoded = url_decode(args.headers)
    if decoded then
        local parsed, err = cjson.decode(decoded)
        if parsed and type(parsed) == "table" then
            headers = parsed
        else
            ngx.status = 400
            ngx.header["Content-Type"] = "application/json"
            ngx.say('{"error": "invalid_headers_format"}')
            return ngx.exit(400)
        end
    end
end

if not decoded_url then
    ngx.status = 400
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "missing_url_parameter"}')
    return ngx.exit(400)
end

-- Fetch M3U8
local httpc = http.new()
httpc:set_timeout(15000)

local target_host = decoded_url:match("https?://([^/]+)")
local base_url = decoded_url:match("(.+//[^/]+/[^/]*/)") or decoded_url:match("(.+//[^/]+/)") or decoded_url

-- Browser headers
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

for k, v in pairs(headers) do
    local key = k:lower()
    if key ~= "host" then
        req_headers[key] = v
    end
end
if not req_headers["referer"] and req_headers["origin"] then
    req_headers["referer"] = req_headers["origin"]
end

local res, err = httpc:request_uri(decoded_url, {
    method = "GET",
    headers = req_headers,
    ssl_verify = false,
})

if not res then
    ngx.status = 502
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "connection_failed"}')
    return ngx.exit(502)
end

if res.status == 403 and res.body and res.body:match("Cloudflare") then
    ngx.status = 403
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "blocked_by_cloudflare"}')
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

-- Convert relative to absolute URL
local function to_absolute_url(relative, base)
    if not relative then return base end
    if relative:match("^https?://") then
        return relative
    end
    if relative:match("^/") then
        local domain = base:match("^(https?://[^/]+)")
        return domain .. relative
    end
    local base_dir = base:match("(.+/.+/)") or base:match("(.+/.*)/") or base
    return base_dir .. relative:gsub("^%.?/", "")
end

-- Build proxy URL (MATCHES YOUR ROUTES)
local function build_proxy_url(abs_url, proxy_type)
    local extension = proxy_type == "ts-proxy" and ".ts" or ".m3u8"
    return proxy_host .. "/" .. proxy_type .. extension .. "?url=" .. ngx.escape_uri(abs_url) .. "&headers=" .. encoded_headers
end

-- Process M3U8
local lines = {}
local next_is_segment = false

for line in content:gmatch("[^\r\n]+") do
    local output = line
    
    if line ~= "" and not line:match("^#") then
        local abs_url = to_absolute_url(line, base_url)
        
        local proxy_type
        if next_is_segment then
            proxy_type = "ts-proxy"
            next_is_segment = false
        elseif line:match("%.m3u8$") or line:match("%.m3u$") then
            proxy_type = "m3u8-proxy"
        elseif line:match("%.ts$") or line:match("%.m4s$") or line:match("%.aac$") or line:match("%.mp4$") or line:match("%.vtt$") then
            proxy_type = "ts-proxy"
        else
            proxy_type = "m3u8-proxy"
        end
        
        output = build_proxy_url(abs_url, proxy_type)
        
    elseif line:match("^#EXTINF") or line:match("^#EXT%-X%-BYTERANGE") then
        next_is_segment = true
        
    elseif line:match("^#EXT%-X%-KEY") or line:match("^#EXT%-X%-MAP") or line:match("^#EXT%-X%-PART") then
        local uri = line:match('URI="([^"]+)"')
        if uri then
            local abs_uri = to_absolute_url(uri, base_url)
            local is_seg = uri:match("%.ts$") or uri:match("%.m4s$")
            local ptype = is_seg and "ts-proxy" or "m3u8-proxy"
            local proxied = build_proxy_url(abs_uri, ptype)
            output = line:gsub('URI="[^"]+"', 'URI="' .. proxied .. '"')
        end
    end
    
    table.insert(lines, output)
end

ngx.header["Content-Type"] = "application/vnd.apple.mpegurl"
ngx.header["Cache-Control"] = "no-cache"
ngx.say(table.concat(lines, "\n"))
