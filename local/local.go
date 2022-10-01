package local

import (
	"encoding/binary"
	"log"
	"net"
	"regexp"
	"strconv"

	"lightsocks"
)

type LsLocal struct {
	Cipher     *lightsocks.Cipher
	ListenAddr *net.TCPAddr
	RemoteAddr *net.TCPAddr
}

// 新建一个本地端
// 本地端的职责是:
// 1. 监听来自本机浏览器的代理请求
// 2. 转发前加密数据
// 3. 转发socket数据到墙外代理服务端
// 4. 把服务端返回的数据转发给用户的浏览器
func NewLsLocal(password, listenAddr, remoteAddr string) (*LsLocal, error) {
	bsPassword, err := lightsocks.ParsePassword(password)
	if err != nil {
		return nil, err
	}
	structListenAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	structRemoteAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return nil, err
	}
	return &LsLocal{
		Cipher:     lightsocks.NewCipher(bsPassword),
		ListenAddr: structListenAddr,
		RemoteAddr: structRemoteAddr,
	}, nil
}

// 本地端启动监听，接收来自本机浏览器的连接
func (local *LsLocal) Listen(didListen func(listenAddr *net.TCPAddr)) error {
	return lightsocks.ListenEncryptedTCP(local.ListenAddr, local.Cipher, local.handleConn_lu_socks5, didListen)
}

func (local *LsLocal) handleConn(userConn *lightsocks.SecureTCPConn) {
	defer userConn.Close()

	// 链接代理服务器
	proxyServer, err := lightsocks.DialEncryptedTCP(local.RemoteAddr, local.Cipher)
	if err != nil {
		log.Println(err)
		return
	}
	defer proxyServer.Close()

	// 进行转发
	// 从 proxyServer 读取数据发送到 localUser
	go func() {
		err := proxyServer.DecodeCopy(userConn)
		if err != nil {
			// 在 copy 的过程中可能会存在网络超时等 error 被 return，只要有一个发生了错误就退出本次工作
			userConn.Close()
			proxyServer.Close()
		}
	}()
	// 从 localUser 发送数据发送到 proxyServer，这里因为处在翻墙阶段出现网络错误的概率更大
	userConn.EncodeCopy(proxyServer)

}

func (local *LsLocal) handleConn_lu_socks5(userConn *lightsocks.SecureTCPConn) {
	defer userConn.Close()

	// 链接代理服务器
	proxyServer, err := lightsocks.DialEncryptedTCP(local.RemoteAddr, local.Cipher)
	if err != nil {
		log.Println(err)
		return
	}
	defer proxyServer.Close()
	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 判断报文是否符合socks5
	buf := make([]byte, 256)
	n, err := userConn.Read(buf)
	if err != nil {
		return
	}
	istrue, err := regexp.Match(`CONNECT`, buf)
	if err != nil {
		return
	}
	if istrue {

		///////////////////////////////////////////////////////////////////////////////////////////////////////////
		// 封装一个socks5 本地协议,通过刚建立的TCP代理服务器, 建立Socks5 通道

		/* 发送一个版本标识符/方法选择消息。

		   +----+----------+----------+
		   |VER | NMETHODS | METHODS  |
		   +----+----------+----------+
		   | 1  |    1     | 1 to 255 |
		   +----+----------+----------+

		   VER字段被设置为X'05'，用于该版本的协议。 NMETHODS字段包含出现在METHODS字段中的方法标识符的数量。

			METHODS：表示客户端支持的验证方式，可以有多种,目前支持的验证方式共有：
			0x00：NO AUTHENTICATION REQUIRED（不需要验证）
			0x01：GSSAPI
			0x02：USERNAME/PASSWORD（用户名密码）
			0x03: to X'7F' IANA ASSIGNED
			0x80: to X'FE' RESERVED FOR PRIVATE METHODS
			0xFF: NO ACCEPTABLE METHODS（都不支持，没法连接了）
		*/
		//这里将已知的判断全部写上
		proxyServer.EncodeWrite([]byte{0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x80, 0xFF})

		/* 服务器从METHODS中给出的方法中选择一个，并发送一个METHOD选择消息。

		                         +----+--------+
		                         |VER | METHOD |
		                         +----+--------+
		                         | 1  |   1    |
		                         +----+--------+
				如果选择的METHOD是X'FF'，则客户端列出的方法都不能接受，客户端必须关闭连接。
				否则, 客户和服务器进入一个特定方法的子协商。
		*/
		// 只要确确认收到socks5请求即可;  由于服务端默认METHODS = 0x00返回,  故我们客户端这边也不进行任何关于METHOD的验证 (按标准协议,是需要进行单独备忘录表单协商的, 每个依赖都要有方法实现的)
		_, err = proxyServer.DecodeRead(buf)

		if err != nil || buf[0] != 0x05 {
			return
		}

		/* SOCKS请求的形成方式如下。

		   +----+-----+-------+------+----------+----------+
		   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		   +----+-----+-------+------+----------+----------+
		   | 1  |  1  | X'00' |  1   | Variable |    2     |
		   +----+-----+-------+------+----------+----------+
		*/
		// 上一步涉及的多种依赖已略过, 我们不需要任何验证,直接开始发请求。
		////****************************************这一步移到开头, 为匹配socks5两种形式的转发
		//// n, err := userConn.Read(buf)
		//// if err != nil {
		//// 	return
		//// }
		////**********************************
		// if n == net.IPv4len {
		// 	proxyServer.EncodeWrite(append([]byte{0x05, 0x01, 0x00, 0x03}, buf...))
		// }
		// 只使用   ATYP = 0x03 的 DOMAINNAME 域名链接   ,端口号仅支持https的 443端口,  不支持http的 80端口

		reg := regexp.MustCompile(`Host:(.*)\r`)
		result := reg.FindAllStringSubmatch(string(buf[0:n]), -1)
		var addr_test string
		var port_test string
		for _, text := range result {

			addr_test = text[1]

		}
		reg = regexp.MustCompile(`(.*):(.*)`)
		result = reg.FindAllStringSubmatch(addr_test, -1)
		for _, text := range result {
			addr_test = text[1]
			port_test = text[2]
			// fmt.Println(addr_test, "||||||", port_test)     //测试时查看addr与port的相关解析
		}
		b := []byte(addr_test)
		c, _ := strconv.Atoi(port_test)
		d := make([]byte, 2)
		binary.BigEndian.PutUint16(d, uint16(c))

		// fmt.Println(b, string(b))
		// fmt.Println(d, string(d))
		a := append(append([]byte{0x05, 0x01, 0x00, 0x03}, b...), d...)
		// fmt.Println("remote:", string(a[4:len(a)-2]))
		proxyServer.EncodeWrite(a)
		// lu := make([]byte, 256)
		// len := copy(lu, buf[0:n])
		// fmt.Println("sssssssssssss111|| ", string(lu[0:len]), "长度", len)
		/* VER 我们使用0X05  代表socks5 */
		/* 服务端CMD仅支持0X01的CONNECT  (CMD代表客户端请求的类型，值长度也是1个字节，有三种类型  CONNECT: 0x01; BIND: 0.02; UDP:0x03) */
		/*RSV为长度1个字节的保留字, 无需理睬*/
		/*ATYP：代表请求的远程服务器地址类型，值长度1个字节，有三种类型: (IPV4： address: 0x01；  |   DOMAINNAME: 0x03；  |   IPV6： address: 0x04；) */

		/**
		  +----+-----+-------+------+----------+----------+
		  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		  +----+-----+-------+------+----------+----------+
		  | 1  |  1  | X'00' |  1   | Variable |    2     |
		  +----+-----+-------+------+----------+----------+
					ATYP：代表请求的远程服务器地址类型，值长度1个字节，有三种类型
					IP V4 address： 0x01
					DOMAINNAME： 0x03
					IP V6 address： 0x04
		*/
		// 如果服务端链接成功, 将返回此格式
		// 目前仅支持IPV4 ATYP只判断0x01  ,此步骤我们只判断VER 0x05、REP 0x00 代表成功( 0x00 succeeded,   |   0x01 general SOCKS server failure,   |   0x02 connection not allowed by ruleset................)
		n, err = proxyServer.DecodeRead(buf)
		if n < 7 || err != nil {
			return
		}
		if buf[0] != 0x05 || buf[1] != 0x00 || buf[3] != 0x01 {
			return
		} else {
			//给浏览器返回http链接就绪报文, 提示代理通道建立成功, 可以再后续正常发送请求信息了
			userConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		}

		///////////////////////////////////////////////////////////////////////////////////////////////////////////
	} else {
		//继续转发建立链接的消息
		proxyServer.EncodeWrite(buf[0:n])

	}
	// 进行转发
	// 从 proxyServer 读取数据发送到 localUser
	go func() {
		err := proxyServer.DecodeCopy(userConn)
		if err != nil {
			// 在 copy 的过程中可能会存在网络超时等 error 被 return，只要有一个发生了错误就退出本次工作
			userConn.Close()
			proxyServer.Close()
		}
	}()
	// for {
	// 	n, err = userConn.Read(buf)
	// 	if err != nil {
	// 		return
	// 	}
	// 	fmt.Println("之前", buf[0:n], string(buf[0:n]))
	// }
	// 从 localUser 发送数据发送到 proxyServer，这里因为处在翻墙阶段出现网络错误的概率更大
	userConn.EncodeCopy(proxyServer)
}
