-- Copyright (C) Pengfei Xu (ThomasXu18)

-- https://www.w3.org/TR/cors/

local join  = table.concat
local req   = ngx.req

local _M = {_VERSION = '0.10'}

-- response headers
local ac_allow_origin       = 'Access-Control-Allow-Origin'
local ac_expose_headers     = 'Access-Control-Expose-Headers'
local ac_max_age            = 'Access-Control-Max-Age'
local ac_allow_credentials  = 'Access-Control-Allow-Credentials'
local ac_allow_methods      = 'Access-Control-Allow-Methods'
local ac_allow_headers      = 'Access-Control-Allow-Headers'
-- request headers
local origin                = 'Origin'
local ac_req_headers        = 'Access-Control-Request-Headers'
local ac_req_method         = 'Access-Control-Request-Method'

-- default settings
-- default allow all hosts
-- '*.a.com' --> '[%d%a%.%-]*%.a%.com' 或者 'a%.com'
local allow_hosts       = {'*'}
local allow_hosts_regs   = {}
local allow_all_hosts   = true
local allow_headers     = {'*'}
local allow_all_headers = true
local allow_methods     = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}
local expose_headers    = {}
local max_age           = 3600
local allow_credentials = true

local function has_value (tab, val)
    for _, value in ipairs(tab) do
        if value == val then
            return true
        end
    end
    return  false
end

local function check_origin(req_origin)
    if allow_all_hosts then
        return true
    end

    if #allow_hosts_regs == 0 then
        for _, h in ipairs(allow_hosts) do
            local d = d:match('^%*%.([%a%d%.%-]+)$')
            if d then
                d = d:gsub('%.', '%%.')
                allow_hosts_regs[#allow_hosts_regs+1] = d
                allow_hosts_regs[#allow_hosts_regs+1] = '[%a%d%.%-]+'..d
            end
        end
    end

    if has_value(allow_hosts, req_origin) then
        return true
    end

    for _, reg in ipairs(allow_hosts_regs) do
        if req_origin:match(reg) then
            return true
        end
    end

    return false
end

local function check_method(method)
    return has_value(allow_methods, method)
end

local function split(str)
    local r = {}
    for w in string.gmatch( str,"([^',']+)") do
        table.insert(r, w)
    end
    return r
end

local function simple_req()
    local method = req.get_method()
    return check_method(method)
end

local function preflight_req(req_method)
    if not req_method or not check_method(req_method) then
        return false
    end
    --[[ Since the `list of methods` can be unbounded,
    simply returning the method indicated by 
    `Access-Control-Request-Method`(if supported) can be enough.
    --]] 
    ngx.header[ac_allow_methods] = req_method

    local req_headers = req.get_headers()[ac_req_headers]
    if req_headers then
        --[[ Since the `list of headers` can be unbounded,
        simply returing supported headers from
        `Access-Control-Allow-Headers` can be enough.
        --]]
        ngx.header[ac_allow_headers] = req_headers
    end

    return true
end

--[[
local cors = reuqire('retry.cors')

cors.init({
    'origin': {'*'},
    'headers': {'*'},
    'methods': {'GET', 'POST'}
    'max_age': 3600,
    'allow_credentials': true,
})
--]]
function _M.init(conf)
    if type(conf) ~= table then
        return
    end
    for k, v in pairs(conf) do
        if k == 'origin' and type(v) == 'table' and #v > 0 then
            allow_hosts = v
        else if k == 'headers' and type(v) == 'table' and #v > 0 then
            allow_headers = v 
        else if k == 'methods' and type(v) == 'table' and #v > 0 then
            allow_methods = v
        else if k == 'max_age' then
            max_age = v | max_age
        else if k == 'allow_credentials' then
            allow_credentials = v | allow_credentials
        end 
    end

    allow_all_hosts = has_value(allow_hosts, '*')
    allow_all_headers = has_value(allow_headers, '*')
end

function _M.filter()
    -- check origin first
    local req_origin = req.get_headers()[origin]

    -- do nothing if request don't have origin header
    if not req_origin then return end
    
    if allow_all_hosts or has_value(allow_hosts, req_origin) then
        -- set response header if origin is allowed.
        -- TODO: Support for configuring regular expressions to match origin
        ngx.header[origin] = req_origin
    else
        -- invalid cors. return 403.
        ngx.exit(403)
    end

    local method = req.request_method
    local is_valid = false
    local is_preflight = false
    local req_method = req.get_headers()[ac_req_method]
    if method == 'OPTIONS' and not req_method then
        is_valid = preflight_req(req_method)
    else
        is_valid = simple_req()
    end

    -- invalid cors. return 403.
    if not is_valid then
        ngx.exit(403)
    end

    -- set `Access-Control-Max-Age` header
    ngx.header[ac_max_age] = max_age

    -- set `Access-Control-Allow-Credentials` heder
    if allow_credentials == true then
        ngx.header[ac_allow_credentials] = 'true'
    else
        ngx.header[ac_allow_credentials] = 'false'
    end

    -- set `Access-Control-Expose-Headers` header
    if #expose_headers > 0 then
        ngx.header[ac_expose_headers] = join(expose_headers, ',')
    end
    
    -- exit with code 200 if preflight request is valid.
    if is_preflight then
        ngx.exit(200)
    end
end

return _M