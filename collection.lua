---第一阶段:lua提取相应信息,写日志,推送分析中心,分析结果入库,页面ui呈现---
---第二阶段:lua提取相应信息,将信息实时写入队列,分析端读取队列进行分析,分析结果入库,页面ui呈现;该阶段目的:实时、---
---第三阶段:lua加入触发防护功能,页面人工确认后，通过页面触发,lua对于某类访问进行直接防护---
---第三阶段二期:如果分析结果效果有效的情况下,进行线下和线上互动,把攻击量引入QA安全测试,进行自动化模拟攻击测试,进行线下回归测试---
local l_query_string = nil
local l_request_body = nil
local method = ngx.req.get_method()
local str_headers = ""
local STR = "body too large"
if method=="POST" then
	content_length = tonumber(ngx.req.get_headers()['content-length'])
	---content_length会存在比实际大少少的情况,暂不对这情况进行控制,该大少通过测试后慢慢调整,如果超与nginx chunk大少,重新考虑读取body方式---
	if content_length > 30720 then
		ngx.log(ngx.CRIT , STR)
		return
	end
end
if ngx.var.query_string == nil then
	l_query_string = ""
else
	l_query_string = string.gsub(ngx.var.query_string,"\"","")
end
if ngx.var.request_body == nil then
	l_request_body = ""
else
	---暂定位于30k左右大少的body,该大少应该不会启动nginx的缓存文件功能,所以,直接使用request_body,而不用read body模式进行---
	l_request_body = string.gsub(ngx.var.request_body,"\"","")
end

t_target = "{\"host\":\""..ngx.var.host.."\",\"remote_addr\":\""..ngx.var.remote_addr.."\",\"server_addr\":\""..ngx.var.server_addr.."\",\"uri\":\""..ngx.var.uri.."\",\"uri_args\":\""..l_query_string.."\",\"body\":\""..l_request_body.."\",\"raddr\":\""..ngx.var.remote_addr.."\","
local headers = ngx.req.get_headers()
for k,v in pairs(headers) do
        if type(v) == "table" then
                str_headers = str_headers.."\""..k.."\":\""..string.gsub(v,"\"","").."\","
        else
                str_headers = str_headers.."\""..k.."\":\""..string.gsub(v,"\"","").."\","
        end
end
str_headers = string.sub(str_headers,0,string.len(str_headers)-1)
t_target = t_target.."\"headers\":[{"..str_headers.."}]}"
---第一阶段目标是能实现功能看看效果,不引入实时队列方式,直接写日志;本次重用nginx的日志线程,不用lua的file写文件功能增加额外线程---
ngx.log(ngx.CRIT , t_target)
