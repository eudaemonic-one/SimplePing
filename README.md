# Simple Implementation of Ping tool for Linux OS

Linux ping命令可以作为检查网络是否联通，分析和判定网络故障的基本工具。

PING（Packet Internet Groper）命令是向某个（些）IP地址发送一个包含有ICMP Echo消息的ICMP（Internet Control Messages Protocol）协议包，等待接收该节点返回的ICMP Echo reply消息的命令。

**语法**

> ping [-bdDfhnqrUvc][-c<完成次数>][-i<间隔秒数>][-p<范本样式>][-Q<服务质量>][-s<数据包大小>][-S<发送缓冲大小>][-t<存活数值>][w<超时时间>][W<发送超时>] [主机名称或IP地址]

**参数说明：**
* -b
  * 解释：允许ping程序尝试连接一个广播地址。
  * 参数：无。
  * 输入样例：ping -b 255.255.255.255
  * 预期结果：收到来自本机所在网段的其他主机返回的ICMP包并输出数据报信息。

* -c count
  * 解释：在发送指定数目count个ECHO_REQUEST数据报后停止。
  * 参数：int count，指定的ECHO_REQUEST数据报数目，初始值为4096。
  * 输入样例：ping -c100 www.baidu.com 
  * 预期结果：发送count个ECHO_REQUEST数据报到指定的 www.baidu.com ，收到来自 www.baidu.com 返回的包含ECHO_RESPONSE信息的ICMP数据报，并输出数据报信息。
  * 备注：配合deadline选项，ping等待发送完毕count个ECHO_REPLY数据报，直到超时到期。

* -d
  * 解释：设置socket套接口的SO_DEBUG选项（这个套接口选项不会在Linux内核中被使用）。
  * 参数：无。
  * 输入样例：ping -d www.baidu.com
  * 预期结果：按照默认间隔时间1s发送ICMP数据报到指定地址，收到来自 www.baidu.com 返回的包含ECHO_RESPONSE信息的ICMP数据报，其中包含DEBUG信息，并输出数据报信息。

* -D
  * 解释：在每行之前打印时间戳。
  * 参数：无。
  * 输入样例：ping -D www.baidu.com
  * 预期结果：按照默认间隔时间1s发送ICMP包到指定的 www.baidu.com ，收到来自 www.baidu.com 返回的包含ECHO_RESPONSE信息的ICMP数据报，并先后输出时间戳和对应收到的数据报信息，。

* -f
解释：极限检测ping。对任意ECHO_REQUEST发送打印一个‘.’，当收到任意一个ECHO_REPLY的ICMP数据报时回退一个字符位。这个选项提供了快速展示数据报丢失的原  * 因。
  * 参数：无。
  * 输入样例：ping -f www.baidu.com
  * 预期结果：按照极限速度flood_interval发送ICMP数据报到指定的 www.baidu.com ，发送速度不小于每秒100次，当发送时打印‘.’，当收到返回时退格，最后显示的‘.’

* -h
  * 解释：显示帮助信息。
  * 参数：无。
  * 输入样例：ping -h www.baidu.com
  * 预期结果：打印出ping程序的帮助信息“ping usage: ...”。

* -i interval
  * 解释：每等待interval秒发送一个数据报。默认等待时间间隔是1秒，或者在极限检测中等待。
  * 参数：double interval
  * 输入样例：ping -i5 www.baidu.com
  * 预期结果：按照5秒的时间间隔定时发送ICMP数据报到指定地址，收到来自 www.baidu.com 返回的包含ECHO_RESPONSE信息的ICMP数据报，并输出数据报信息。

* -n
  * 解释：只输出主机地址的数码形式，不会尝试去寻找主机的符号名。
  * 参数：无。
  * 输入样例：ping -n www.baidu.com
  * 预期结果：只打印 www.baidu.com 的IP地址的数字形式，不打印主机名，即www.baidu.com 。

* -p pattern
  * 解释：根据指定的pattern填充单元按照填满pad的16字节。这有助于诊断网络中与数据无关的问题。例如-p “ff”会导致发送数据报被填充为全1。
  * 参数：int pattern
  * 输入样例：ping -p “ff” www.baidu.com
  * 预期结果：发送ICMP数据字段中填满全1的数据包到指定的www.baidu.com 。

* -q
  * 解释：静默输出。不打印除了开端、末尾总结行之外的内容。
  * 参数：无。
  * 输入样例：ping -q www.baidu.com
  * 预期结果：只打印开端和末尾的总结行“ping statistics ...”。

* -Q tos
  * 解释：设置与ICMP数据报比特流相关的服务质量QoS（Quality of Service）。
  * 参数：int tos
  * 输入样例：ping -Q10 www.baidu.com
  * 预期结果：发送ICMP数据字段中服务质量QoS为10的数据包到指定的www.baidu.com 。

* -r
  * 解释：忽略正常的路由表并直接发送到一个直接连接的目的主机。如果该主机不在直接连接的网络中，会产生错误。这个选项可以被用来通过一个没有路由的并且使用选项-I的接口ping一个本地主机。
  * 参数：无。
  * 输入样例：ping -r www.baidu.com
  * 预期结果：尝试连接非在本地网络的主机 www.baidu.com 时每发送一个包含ECHO_REQUEST的ICMP数据报时输出“Network is unreachable”表示该网络不可达。

* -s packetsize
  * 解释：明确发送的数据字节数packetsize。默认值为56，该数据报在添加ICMP头部的8字节数据后被转换为64字节的ICMP数据。
  * 参数：int packetsize
  * 输入样例：ping -r www.baidu.com
  * 预期结果：发送ICMP数据字段中数据字段为56字节的数据报到指定的www.baidu.com。

* -S sndbuf
  * 解释：设置socket套接口发送缓冲区大小sndbuf。如果sndbuf没有被明确声明，则它被指定不缓存多于一个数据报。
  * 参数：int sndbuf
  * 输入样例：ping -s10 www.baidu.com
  * 预期结果：发送ICMP数据字段的socket套接口的发送缓冲区大小被设置为10。

* -t ttl
  * 解释：设置ping的IP生存时间值（Time to Live）。
  * 参数：int ttl
  * 输入样例：ping -t12 www.baidu.com
  * 预期结果：收到默认生存时间值ttl为128的包含ECHO_REPLY的ICMP数据报。

* -v
  * 解释：冗余输出。打印除了包含ECHO_RESPONSE的ICMP数据报，和所有返回的ICMP数据报。
  * 参数：无。
  * 输入样例：ping -v www.baidu.com
  * 预期结果：有可能会打印出不带ECHO_RESPONSE标记且icmp_id不为发送进程号的ICMP包。

* -V
  * 解释：显示ping版本并退出。
  * 参数：无。
  * 输入样例：ping -V www.baidu.com
  * 预期结果：显示ping的版本号为“s20180702”并退出。

* -U
  * 解释：输出用户到用户的完整延迟时间。通常ping输出网络的往返时延（Round-trip Time），这有可能会与前者不同。
  * 参数：无。
  * 输入样例：ping -U www.baidu.com
  * 预期结果：在每次打印ICMP数据报信息时输出完整延迟时间time，这个值往往比在使用默认ping程序的rtt大。

* -w deadline
  * 解释：明确声明一个在ping程序退出之前无论多少数据报被发送和接收的超时时间timeout，单位时间为秒。在这里ping不会在count个包被发送前停止，ping会等待deadline过期或直到count探针被应答或网络中出现错误为止。
  * 参数：double deadline
  * 输入样例：ping -w10 www.baidu.com
  * 预期结果：ping程序在经过10s（10次发送ICMP数据报）后退出。

* -W timeout
  * 解释：明确一个等待回复的超时时间timeout，单位时间为秒。这个选项只影响没有回复情况下的超时时间，否则ping会等待两个往返时延（RTT）。
  * 参数：double timeout
  * 输入样例：ping -W1 192.168.1.100 （注：192.168.1.100为本地网络中无法连接的主机地址）
  * 预期结果：每次发送一个ICMP数据报后打印“From localhost: Time to live exceeded\n”。
