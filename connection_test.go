package mysql_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
)

type Handshake struct {
	//1byte 协议版本号
	protocolVersion byte
	//n byte 服务版本信息（Null-Termimated-String） 服务端所使用的mysql协议的版本号
	version string
	//4 bytes 服务器线程id 服务端为此客户端所创建的线程的ID
	threadId int
	//8 bytes随机挑战数 MySQL数据库用户认证采用的是挑战/应答的方式，
	//服务器生成该挑战数并发送给客户端，由客户端进行处理并返回相应结果
	//，然后服务器检查是否与预期的结果相同，从而完成用户认证的过程。
	salt1 string
	//1 byte 填充值（0x00）
	fill uint8
	//2 bytes 服务器权能标志（低16位） 用于与客户端协商通讯方式
	//https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
	capabilitiesLow int
	// 1 byte 字符编码
	//https://dev.mysql.com/doc/internals/en/character-set.html#packet-Protocol::CharacterSet
	charset byte
	//2 bytes 服务器状态
	//https://dev.mysql.com/doc/internals/en/status-flags.html#packet-Protocol::StatusFlags
	status int
	// 2 bytes 服务器权能标志（高16位）
	// https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
	capabilitiesHigh int
	//随机挑战数(12位)
	salt2 string
	//
	pluginName string
}

func ReadPackage(conn net.Conn) ([]byte, error) {

	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	bodyLength := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	body := make([]byte, bodyLength)

	n, err := io.ReadFull(conn, body)
	if err != nil {
		return nil, err
	}

	return append(header, body[0:n]...), nil
}

func SkipHeaderPackage(r *bytes.Reader) error {
	if _, err := r.Seek(4, io.SeekStart); err != nil {
		return err
	}
	return nil
}

func ReadNullTerminatedString(r *bytes.Reader) string {
	var str []byte
	for {
		b, _ := r.ReadByte()
		if b == 0x00 {
			return string(str)
		} else {
			str = append(str, b)
		}
	}
}

type HandResponse struct {
	//capability flags, CLIENT_PROTOCOL_41 always set
	capabilityFlags [4]byte

	maxPackageSize [4]byte
	//字符串集
	characterSet byte
	//保留字段 Filler [23 bytes] (all 0x00)
	reserved [23]string
	//user string[NUL]结尾
	user      string
	// if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA {
	//lenenc-int     length of auth-response
	//string[n]      auth-response
	//  } else if capabilities & CLIENT_SECURE_CONNECTION {
	//1              length of auth-response
	//string[n]      auth-response
	//  } else {
	//string[NUL]    auth-response
	//  }
	lenencInt [9]byte
	//string[n] password加密结果串
	authResponse []byte
	//string[Nul]
	database string
	//认证插件名称
	authPluginName string
}

func auth(handshakePackage Handshake, password string)  {
	scramble := handshakePackage.salt1 + handshakePackage.salt2
	authData := scrambleSHA256Password([]byte(scramble), password)

	clientFlags := clientFla
}

func scrambleSHA256Password(scramble []byte, password string) []byte {
	sha := sha256.New()
	sha.Write([]byte(password))
	m1 := sha.Sum(nil)

	sha.Reset()
	sha.Write(m1)
	m2 := sha.Sum(nil)

	sha.Reset()
	sha.Write(m2)
	sha.Write(scramble)
	m3 := sha.Sum(nil)

	for k := range m3 {
		m1[k] ^= m3[k]
	}
	return m1
}

//切片copy 返回值
func TestCopyReturn(t *testing.T) {
	d := []byte{1, 2, 3}
	p := "q"
	n := copy(d[2:], p)
	fmt.Println(n, d, len(d))
	var q [9]byte
	var f []byte
	fmt.Println(append(q[:0], byte(1), byte(1)), len(f))
}

//for 外层定义的变量值，for循环是否影响到它
func TestForVar(t *testing.T) {
	i := 21
	for ; i < 30; i++ {

	}
	fmt.Println(i)
}

//1月27日切片复制 := 和 copy 区别
func TestSliceCopy(t *testing.T) {
	p := make([]string, 3)
	p[0] = "123"
	p[1] = "321"
	p[2] = "124"
	fmt.Println(p)
	s := p
	s[0] = "321x"

	fmt.Println(s, p)

	l := make([]string, 3)
	for k := range p {
		l[k] = p[k]
	}
	l[0] = "321l"
	copy(l, p)
	fmt.Println(l, p)
}

func readHandshake(lis net.Conn) Handshake {
	body, err := ReadPackage(lis)

	if err != nil {
		log.Fatal(err)
	}

	bodyReader := bytes.NewReader(body)

	err = SkipHeaderPackage(bodyReader)

	if err != nil {
		log.Fatal(err)
	}
	//协议版本
	protocolVersion, err := bodyReader.ReadByte()
	if err != nil {
		log.Fatal(err)
	}
	//服务版本
	serverVersion := ReadNullTerminatedString(bodyReader)

	//服务器线程id
	threadIdBuf := make([]byte, 4)
	bodyReader.Read(threadIdBuf)
	threadId := int(uint32(threadIdBuf[0]) | uint32(threadIdBuf[1])<<8 | uint32(threadIdBuf[2])<<16 | uint32(threadIdBuf[3])<<24)

	//随机挑战数
	saltBuf := make([]byte, 8)
	_, err = bodyReader.Read(saltBuf)
	if err != nil {
		log.Fatal(err)
	}
	//跳过1 byte填充
	bodyReader.Seek(1, io.SeekCurrent)

	//读取 2 byte 服务器权能标识(低16位)
	capabilitiesLowBuf := make([]byte, 2)
	bodyReader.Read(capabilitiesLowBuf)
	capabilitiesLow := int(uint32(capabilitiesLowBuf[0]) | uint32(capabilitiesLowBuf[1])<<8)

	//读取 1 byte 字符编码
	charset, _ := bodyReader.ReadByte()

	//读取 2 byte 服务状态
	serverStatusBuf := make([]byte, 2)
	bodyReader.Read(serverStatusBuf)
	serverStatus := int(uint32(serverStatusBuf[0]) | uint32(serverStatusBuf[1]))

	//读取服务器权能标志(高16位)
	capabilitiesHigh2Buf := make([]byte, 2)
	bodyReader.Read(capabilitiesHigh2Buf)
	capabilitiesHigh := int(uint32(capabilitiesHigh2Buf[0]) | uint32(capabilitiesHigh2Buf[1])<<8)

	//跳过 1byte 未使用的挑战长度
	bodyReader.Seek(1, io.SeekCurrent)

	//跳过10 byte 填充值
	bodyReader.Seek(10, io.SeekCurrent)

	//读取12位挑战随机数
	salt2 := ReadNullTerminatedString(bodyReader)

	//读取密码认证插件
	pluginName := ReadNullTerminatedString(bodyReader)

	return Handshake{
		protocolVersion:  protocolVersion,
		version:          serverVersion,
		threadId:         threadId,
		salt1:            string(saltBuf),
		capabilitiesLow:  capabilitiesLow,
		charset:          charset,
		status:           serverStatus,
		capabilitiesHigh: capabilitiesHigh,
		salt2:            salt2,
		pluginName:       pluginName,
	}
}

func TestConn(t *testing.T) {
	lis, _ := net.Dial("tcp", "127.0.0.1:3306")

	defer lis.Close()

	h := readHandshake(lis)

	fmt.Println(h)
}

func TestUintLeft(t *testing.T) {
	fmt.Println(uint32(128) << 8)
}

func TestData(t *testing.T) {
	BigEndian()
	LittleEndian()
}

func BigEndian() { // 大端序

	// 二进制形式：0000 0000 0000 0000 0001 0002 0003 0004
	var testInt int32 = 0x01020304 // 十六进制表示
	fmt.Printf("%d use big endian: \n", testInt)

	var testBytes []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(testBytes, uint32(testInt)) //大端序模式
	fmt.Println("int32 to bytes:", testBytes)

	convInt := binary.BigEndian.Uint32(testBytes) //大端序模式的字节转为int32
	fmt.Printf("bytes to int32: %d\n\n", convInt)
}

func LittleEndian() { // 小端序
	//二进制形式： 0000 0000 0000 0000 0001 0002 0003 0004
	var testInt int32 = 0x01020304 // 16进制
	fmt.Printf("%d use little endian: \n", testInt)

	var testBytes []byte = make([]byte, 4)
	binary.LittleEndian.PutUint32(testBytes, uint32(testInt)) //小端序模式
	fmt.Println("int32 to bytes:", testBytes)

	convInt := binary.LittleEndian.Uint32(testBytes) //小端序模式的字节转换
	fmt.Printf("bytes to int32: %d\n\n", convInt)
}
