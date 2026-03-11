local _M = {}

local CACHE_DIR = "/cache"
local SIZE_CHECK_INTERVAL = 60  -- Check size every 60 seconds
local last_size_check = 0

-- Simple hash function for cache keys
local function hash_key(str)
    local h = 5381
    for i = 1, #str do
        h = ((h * 33) + string.byte(str, i)) % 0xFFFFFFFF
    end
    return string.format("%08x", h)
end

-- Parse size string (e.g., "5g" -> bytes)
local function parse_size(size_str)
    if not size_str or size_str == "0" then return 0 end
    local num, unit = size_str:match("^(%d+)(%a?)$")
    if not num then return 10 * 1024 * 1024 * 1024 end -- default 10GB

    num = tonumber(num)
    unit = unit:lower()
    if unit == "g" then return num * 1024 * 1024 * 1024
    elseif unit == "m" then return num * 1024 * 1024
    elseif unit == "k" then return num * 1024
    else return num end
end

-- Get cache expiry in seconds from env
local function get_expiry_seconds()
    local expiry = os.getenv("CACHE_EXPIRY") or "2d"
    local num, unit = expiry:match("^(%d+)(%a)$")
    if not num then return 172800 end -- default 2 days

    num = tonumber(num)
    if unit == "d" then return num * 86400
    elseif unit == "h" then return num * 3600
    elseif unit == "m" then return num * 60
    else return num end
end

-- Check if caching is enabled
local function is_enabled()
    local size = os.getenv("CACHE_SIZE") or "10g"
    return size ~= "0"
end

-- Get max cache size in bytes
local function get_max_size()
    local size = os.getenv("CACHE_SIZE") or "10g"
    return parse_size(size)
end

-- Ensure cache directory exists
local function ensure_dir(path)
    local dir = path:match("(.*/)")
    if dir then
        os.execute("mkdir -p " .. dir .. " 2>/dev/null")
    end
end

-- Get cache file path for URL
function _M.get_path(url)
    local key = hash_key(url)
    local subdir = key:sub(1, 2)
    return string.format("%s/%s/%s", CACHE_DIR, subdir, key)
end

-- Get current cache size in bytes
local function get_cache_size()
    local handle = io.popen("du -sb " .. CACHE_DIR .. " 2>/dev/null | cut -f1")
    if not handle then return 0 end
    local result = handle:read("*a")
    handle:close()
    return tonumber(result) or 0
end

-- Clean expired files and enforce size limit
local function cleanup_cache()
    local now = os.time()

    -- Don't check too often
    if now - last_size_check < SIZE_CHECK_INTERVAL then
        return
    end
    last_size_check = now

    local expiry = get_expiry_seconds()
    local max_size = get_max_size()
    local current_size = get_cache_size()

    -- First pass: delete expired files
    local cmd = string.format(
        "find %s -type f -mmin +%d -delete 2>/dev/null",
        CACHE_DIR, math.floor(expiry / 60)
    )
    os.execute(cmd)

    -- Second pass: if still over limit, delete oldest files
    current_size = get_cache_size()
    if current_size > max_size then
        -- Delete oldest 20% of files when over limit
        local delete_cmd = string.format(
            "find %s -type f -printf '%%T+ %%p\\n' 2>/dev/null | sort | head -n $(find %s -type f 2>/dev/null | wc -l | awk '{print int($1*0.2)+1}') | cut -d' ' -f2- | xargs rm -f 2>/dev/null",
            CACHE_DIR, CACHE_DIR
        )
        os.execute(delete_cmd)
        ngx.log(ngx.NOTICE, "Cache cleanup: was ", current_size, " bytes, limit ", max_size)
    end

    -- Clean empty directories
    os.execute("find " .. CACHE_DIR .. " -type d -empty -delete 2>/dev/null")
end

-- Check if cached and not expired
function _M.get(url)
    if not is_enabled() then return nil end

    local path = _M.get_path(url)
    local file = io.open(path, "rb")
    if not file then return nil end

    -- Check expiry
    local handle = io.popen("stat -c %Y " .. path .. " 2>/dev/null")
    local attr = handle and handle:read("*a") or ""
    if handle then handle:close() end

    local mtime = tonumber(attr)
    if mtime then
        local age = os.time() - mtime
        if age > get_expiry_seconds() then
            file:close()
            os.remove(path)
            return nil
        end
    end

    -- Read metadata (first line: content-type)
    local content_type = file:read("*l")
    local body = file:read("*a")
    file:close()

    return {
        content_type = content_type,
        body = body
    }
end

-- Store in cache
function _M.set(url, content_type, body)
    if not is_enabled() then return end
    if not body or #body == 0 then return end

    -- Run cleanup check before writing
    cleanup_cache()

    -- Check if we have space (quick check)
    local current_size = get_cache_size()
    local max_size = get_max_size()
    if current_size + #body > max_size then
        -- Force cleanup
        last_size_check = 0
        cleanup_cache()
    end

    local path = _M.get_path(url)
    ensure_dir(path)

    local file = io.open(path, "wb")
    if not file then
        ngx.log(ngx.WARN, "Failed to write cache: ", path)
        return
    end

    -- Write metadata + body
    file:write(content_type or "application/octet-stream")
    file:write("\n")
    file:write(body)
    file:close()
end

-- Get cache status for headers
function _M.status(url)
    if not is_enabled() then return "DISABLED" end
    local path = _M.get_path(url)
    local file = io.open(path, "rb")
    if file then
        file:close()
        return "HIT"
    end
    return "MISS"
end

return _M
