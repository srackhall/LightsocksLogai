****
LightsocksLogai仅在原[Lightsocks](https://github.com/gwuhaolin/lightsocks)项目基础上, 简单添加了socks5协议的请求端的适配代码, 使得可以直接使用windows的系统代理配置来访问代理(因个人偶尔的使用需求添加,不过由于会占用一定的系统资源,所以平时还是以Lightsocks为主), 并且不影响与SwitchyOmega或其他socks5客户端的配合使用。LightsocksLogai配置文件默认名改为`.lightsocksLogai.json`,与使用的Lightsocks做简单区分。

[Lightsocks](https://github.com/gwuhaolin/lightsocks)是以个在socks5基础上利用置换字节表方式混淆加密的代理项目(好像是为帮助大家了解Shadowsocks而发起的)。 不过由于lightsocks只做了简单的加密处理,且代理实现上也没做过多的适配, 不会消耗太多系统资源, 因此应该非常适合个人使用, 毕竟单独少量的tcp链接无需考虑被侦测, 其实以前试过直接socks5裸奔也没问题(不过风险过高不推荐,衣服再薄也比不穿强)。
****