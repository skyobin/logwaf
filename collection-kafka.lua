local l_query_string = nil
local l_request_body = nil
local method = ngx.req.get_method()
local str_headers = ""
--local queue_name = "logwaf-test"
local queue_name = ngx.var.queuename
local local_time = os.date("%Y-%m-%d %H:%M:%S", os.time())
local banned = ngx.shared.banned
if banned:get(ngx.var.remote_addr) then
	ngx.exit(ngx.HTTP_FORBIDDEN)
elseif banned:get(ngx.md5(ngx.var.http_user_agent)) then
	ngx.exit(ngx.HTTP_FORBIDDEN)
elseif banned:get(ngx.md5(ngx.var.http_referer)) then
	ngx.exit(ngx.HTTP_FORBIDDEN)
end
local cookievalue = "none"
if  ngx.var.http_cookie ~= nil then
    cookievalue = ngx.unescape_uri(ngx.var.http_cookie)
    cstart = string.find(cookievalue,"pcsuv=")
    cend = string.find(cookievalue,";",cstart)
    if cstart ~= nil and cend ~= nil then
        pcsuv = string.sub(cookievalue , cstart , cend-1)
        if pcsuv ~= "pcsuv=" then
           if banned:get(pcsuv) then
               ngx.exit(ngx.HTTP_FORBIDDEN)
           end
        end
    end
end
local ruledb = ngx.shared.ruledb
function block(mytype,content,locate)
	local rulearry = ruledb:get(mytype)
	if rulearry == nil then return end
	local i = 0
	local j = 0
	while true do
            i = string.find(rulearry , ",", i+1)
            if i == nil then i = string.len(rulearry) end
            local key = nil
            if i == string.len(rulearry) then
                key = string.sub(rulearry , j+1,i)
            else
                key = string.sub(rulearry , j,i-1)
            end
			local myrule = ruledb:get(key)
			if myrule == nil then break end
			local m, err = ngx.re.match(ngx.unescape_uri(content), myrule)
			if m then
				ngx.exit(ngx.HTTP_FORBIDDEN)
			end
            if i == string.len(rulearry) then break end
            j = i
    end
end
if method=="POST" then
	content_length = tonumber(ngx.req.get_headers()['content-length'])
	if content_length > 30720 then return end
end
if ngx.var.query_string == nil then
	l_query_string = ""
else
	l_query_string = ngx.var.query_string
end
if ngx.var.request_body == nil then
	l_request_body = ""
else
	local args = ngx.req.get_post_args()
	for key, val in pairs(args) do
		if key == "ngix_poster" then return end
	end
	l_request_body = ngx.var.request_body
end
block("scanfeature",ngx.var.http_user_agent,"user_agent")
block("sensitivefile",ngx.var.uri,"uri")
block("adminpage",ngx.var.uri,"uri")
block("sensitivefile",l_query_string,"uri_args")
block("sqlinject",l_query_string,"uri_args")
block("xss",l_query_string,"uri_args")
block("sqlinject",l_request_body,"body")
block("xss",l_request_body,"body")
t_target = "{\"ltime\":\""..local_time.."\",\"method\":\""..method.."\",\"host\":\""..ngx.var.host.."\",\"remote_addr\":\""..ngx.var.remote_addr.."\",\"server_addr\":\""..ngx.var.server_addr.."\",\"uri\":\""..ngx.var.uri.."\",\"uri_args\":\""..l_query_string.."\",\"body\":\""..l_request_body.."\",\"raddr\":\""..ngx.var.remote_addr.."\","
local headers = ngx.req.get_headers()
for k,v in pairs(headers) do
        if type(v) == "table" then
                str_headers = str_headers.."\""..string.lower(k).."\":\""..ngx.escape_uri(table.concat(v, ", ")).."\","
        else
                str_headers = str_headers.."\""..string.lower(k).."\":\""..ngx.escape_uri(v).."\","
        end
end
str_headers = string.sub(str_headers,0,string.len(str_headers)-1)
t_target = t_target.."\"headers\":[{"..str_headers.."}]}"
local client = require "resty.kafka.client"
local producer = require "resty.kafka.producer"
local broker_list = {{ host = "127.0.0.1", port = 9092 }}
local key = ngx.md5(t_target)
local bp = producer:new(broker_list, { producer_type = "async"})
local ok, err = bp:send(queue_name, key, t_target)
if not ok then
	ngx.log(ngx.CRIT , err)
	return
end
---ngx.log(ngx.CRIT , "send success, offset: ")

