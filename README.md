# logwaf

Author：178718287@qq.com

logwaf基于nginx lua做前端防御，基于用户访问行为用hadoop做用户行为分析的waf。

nginx中嵌入lua功能脚本，进行数据采集和拒绝异常可疑访问。

由于分析用户行为代码涉及到公司的防御策略，所以，不进行公布，

有兴趣的可以自行写分析功能程序，然后把分析结果推送到前端nginx中。


collection-kafka.lua ： 用于进行收集用户访问数据和防御功能。
logwaf.conf ： 用于设置、删除、查看防御规则。


例子：

1.添加删除拦截ip

   curl "http://127.0.0.1:8889/LOGWAFBANNEDSET?type=remote_addr&method=add&value=127.0.0.2"
   
   curl "http://127.0.0.1:8889/LOGWAFBANNEDSET?type=remote_addr&method=del&value=127.0.0.2"
   
   type：remote_addr
   
   method：add(添加)|del(删除)
   
   value：目标IP
   
2.添加删除拦截reffer&useragent

   curl -d "http://baidu.com?nima的" "http://127.0.0.1:8889/LOGWAFBANNEDSET?type=reffer&method=add"
   
   curl -d "http://baidu.com?nima的" "http://127.0.0.1:8889/LOGWAFBANNEDSET?type=reffer&method=del"
   
   curl -d "useragent" "http://127.0.0.1:8889/LOGWAFBANNEDSET?type=UA&method=add"
   
   curl -d "useragent" "http://127.0.0.1:8889/LOGWAFBANNEDSET?type=UA&method=del"
   
   type：定向拦截种类；种类有{"UA","reffer"}
   
   method：add(添加)|del(删除)
   
   body；post body中的数据就为特征
   
3.查看拦截规则情况
   curl http://127.0.0.1:8889/LOGWAFBANNEDCONF
   
4.添加删除模式匹配拦截规则
   curl -d '.(bak|inc|old|mdb|sql|backup|java|class|php|asp|xls)' 'http://127.0.0.1:8889/LOGWAFRULESET?type=sensitivefile&method=add'
   
   type：拦截种类与inm图表中的种类要一致；种类有{"xss","sqlinject","scanfeature","adminpage","sensitivefile"}
   
   method：add(添加)|del(删除)
   
   body；post body中的数据就为规则
   
5.添加cookie中以pcsuv作为用户标识的拦截功能
   curl -d "pcsuv=1462322655025.a.305609700" 'http://192.168.236.95:80/LOGWAFBANNEDSET?type=userid&method=add'