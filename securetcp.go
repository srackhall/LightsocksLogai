package lightsocks

import (
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sync"
)

const (
	bufSize = 1024
)

var bpool sync.Pool

func init() {
	bpool.New = func() interface{} {
		return make([]byte, bufSize)
	}
}
func bufferPoolGet() []byte {
	return bpool.Get().([]byte)
}
func bufferPoolPut(b []byte) {
	bpool.Put(b)
}

// 加密传输的 TCP Socket
type SecureTCPConn struct {
	io.ReadWriteCloser
	Cipher *Cipher
}

// 从输入流里读取加密过的数据，解密后把原数据放到bs里
func (secureSocket *SecureTCPConn) DecodeRead(bs []byte) (n int, err error) {
	n, err = secureSocket.Read(bs)
	if err != nil {
		return
	}
	secureSocket.Cipher.Decode(bs[:n])
	return
}

// 把放在bs里的数据加密后立即全部写入输出流
func (secureSocket *SecureTCPConn) EncodeWrite(bs []byte) (int, error) {
	secureSocket.Cipher.Encode(bs)
	return secureSocket.Write(bs)
}

// /////////////////////////////////////////////////////////////////////////////////////////////
// 携带socks5协议的自定义 加密 转发
func (secureSocket *SecureTCPConn) EncodeCopy_lu_socks5(dst io.ReadWriteCloser) error {
	buf_lu := make([]byte, 256)
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)

	for {
		ss_lu := &SecureTCPConn{
			ReadWriteCloser: dst,
			Cipher:          secureSocket.Cipher,
		}
		readCount_lu, errRead := secureSocket.Read(buf_lu)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		/**************************************************************************/

		ss_lu.EncodeWrite([]byte{0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x80, 0xFF})

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
		_, err := ss_lu.DecodeRead(buf)

		if err != nil || buf[0] != 0x05 {
			return err
		}

		/* SOCKS请求的形成方式如下。

		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
		*/
		// 上一步涉及的多种依赖已略过, 我们不需要任何验证,直接开始发请求。 使用我们接收的第一个buf_lu 128字节用正则获取域名和端口
		// if n == net.IPv4len {
		// 	proxyServer.EncodeWrite(append([]byte{0x05, 0x01, 0x00, 0x03}, buf...))
		// }
		// 只使用   ATYP = 0x03 的 DOMAINNAME 域名链接   ,端口号仅支持https的 443端口,  不支持http的 80端口
		reg := regexp.MustCompile(`Host:(.*)\r`)
		result := reg.FindAllStringSubmatch(string(buf_lu[0:readCount_lu]), -1)
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
			fmt.Println(addr_test, "||||||", port_test)
		}
		b := []byte(addr_test)
		fmt.Println(b, string(b))
		a := append(append([]byte{0x05, 0x01, 0x00, 0x03}, b...), 0x01, 0xbb)
		fmt.Println("remote:", string(a[4:len(a)-2]))
		ss_lu.EncodeWrite(a)
		fmt.Println("发送前的值", string(buf_lu[0:readCount_lu]))
		ss_lu.EncodeWrite(buf_lu)
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
		readCount_lu, err = ss_lu.DecodeRead(buf_lu)
		if readCount_lu < 7 || err != nil {
			return err
		}
		if buf_lu[0] != 0x05 || buf_lu[1] != 0x00 || buf_lu[3] != 0x01 {
			return err
		}
		/*****************************************************************/

		readCount, errRead := secureSocket.Read(buf)
		fmt.Println("转发", buf[0:readCount])
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {

			writeCount, errWrite := ss_lu.EncodeWrite(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////

// 从src中源源不断的读取原数据加密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureTCPConn) EncodeCopy(dst io.ReadWriteCloser) error {
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)
	for {
		readCount, errRead := secureSocket.Read(buf)
		fmt.Println("转发", buf, string(buf))
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := (&SecureTCPConn{
				ReadWriteCloser: dst,
				Cipher:          secureSocket.Cipher,
			}).EncodeWrite(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// 从src中源源不断的读取加密后的数据解密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureTCPConn) DecodeCopy(dst io.Writer) error {
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)
	for {
		readCount, errRead := secureSocket.DecodeRead(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := dst.Write(buf[0:readCount])
			fmt.Println("转发", buf, string(buf))
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// see net.DialTCP
func DialEncryptedTCP(raddr *net.TCPAddr, cipher *Cipher) (*SecureTCPConn, error) {
	remoteConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return nil, err
	}
	// Conn被关闭时直接清除所有数据 不管没有发送的数据
	remoteConn.SetLinger(0)

	return &SecureTCPConn{
		ReadWriteCloser: remoteConn,
		Cipher:          cipher,
	}, nil
}

// see net.ListenTCP
func ListenEncryptedTCP(laddr *net.TCPAddr, cipher *Cipher, handleConn func(localConn *SecureTCPConn), didListen func(listenAddr *net.TCPAddr)) error {
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	if didListen != nil {
		// didListen 可能有阻塞操作
		go didListen(listener.Addr().(*net.TCPAddr))
	}

	for {
		localConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		// localConn被关闭时直接清除所有数据 不管没有发送的数据
		localConn.SetLinger(0)
		go handleConn(&SecureTCPConn{
			ReadWriteCloser: localConn,
			Cipher:          cipher,
		})
	}
}
