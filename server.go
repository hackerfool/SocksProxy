package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/bndr/gotabulate"
)

const _version = "0.0.1"

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

type CmdConfig struct {
	ListenHost string
	ListenPort int
}

func main() {
	var (
		showVersion bool
		config      CmdConfig
	)

	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.StringVar(&config.ListenHost, "h", "", "listen host")
	flag.IntVar(&config.ListenPort, "p", 1080, "server port")
	flag.Parse()

	if showVersion {
		fmt.Println(_version)
		return
	}

	listenAddr := fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		panic(err)
	}

	log.Println("socks5 proxy run, on addr:", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("[ERROR]:", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("[ERROR]:", r, "\n", string(debug.Stack()))
		}
	}()

	isClosed := false
	defer func() {
		if !isClosed {
			conn.Close()
		}
	}()
	log.Println("handle conn from:", conn.LocalAddr().String())
	err := handshake(conn)
	if err != nil {
		panic(err)
	}

	_, host, err := getRequest(conn)
	if err != nil {
		panic(err)
	}

	//create conn
	remote, err := net.Dial("tcp", host)
	if err != nil {
		panic(err)
	}

	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		panic(err)
	}

	//transport
	go transport(conn, remote)
	transport(remote, conn)
}

func handshake(conn net.Conn) error {
	// 	+----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     |  1~255   |
	// +----+----------+----------+

	var (
		readN int
		buf   = make([]byte, 257)
		err   error
	)

	//check socks ver
	if readN, err = io.ReadAtLeast(conn, buf, 2); err != nil {
		return err
	}
	if buf[0] != socksVer5 {
		return errVer
	}

	//read methods
	nmethods := int(buf[1])
	msgLen := 2 + nmethods
	if msgLen > readN {
		io.ReadFull(conn, buf[2:msgLen])
	}

	_, err = conn.Write([]byte{0x05, 0x00})
	return err
}

func getRequest(conn net.Conn) (rawAddr []byte, host string, err error) {
	// 	+----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  |   1   |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	const (
		proxyConnect = 1
		proxyBind    = 2
		proxyUDP     = 3

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		ipv4PacketLen = 4 + net.IPv4len + 2
		ipv6PacketLen = 4 + net.IPv6len + 2

		dmaddrStartPos = 5
	)

	var (
		buf    = make([]byte, 263)
		port   = uint16(0)
		n      = 0
		reqLen = -1
	)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err = io.ReadAtLeast(conn, buf, dmaddrStartPos); err != nil {
		return
	}

	//check ver
	if buf[0] != socksVer5 {
		err = errVer
		return
	}

	//check cmd
	switch buf[1] {
	case proxyConnect:
		//tcp connect
	case proxyBind:
		//bind
		err = errCmd
	case proxyUDP:
		//udp
		err = errCmd
	}
	if err != nil {
		return
	}

	dmLen := int(buf[4])

	switch buf[3] {
	case typeIPv4:
		reqLen = ipv4PacketLen
		host = net.IP(buf[4:(ipv4PacketLen - 2)]).String()
		port = binary.BigEndian.Uint16(buf[(ipv4PacketLen - 2):])
	case typeDm:
		reqLen = (4 + 1 + dmLen + 2)
		host = string(buf[dmaddrStartPos:(dmaddrStartPos + dmLen)])
		port = binary.BigEndian.Uint16(buf[(dmaddrStartPos + dmLen):])
	case typeIPv6:
		reqLen = ipv6PacketLen
		host = net.IP(buf[4:(ipv6PacketLen - 2)]).String()
		port = binary.BigEndian.Uint16(buf[(ipv6PacketLen - 2):])
	}

	if n >= reqLen {
		//
	} else if n < reqLen {
		if _, err = io.ReadFull(conn, buf[n:(reqLen-n)]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	switch buf[3] {
	case typeIPv4:
		host = net.IP(buf[4:(ipv4PacketLen - 2)]).String()
		port = binary.BigEndian.Uint16(buf[(ipv4PacketLen - 2):])
	case typeDm:
		host = string(buf[dmaddrStartPos:(dmaddrStartPos + dmLen)])
		port = binary.BigEndian.Uint16(buf[(dmaddrStartPos + dmLen):])
	case typeIPv6:
		host = net.IP(buf[4:(ipv6PacketLen - 2)]).String()
		port = binary.BigEndian.Uint16(buf[(ipv6PacketLen - 2):])
	}

	row := []interface{}{int(buf[0]), int(buf[1]), int(buf[2]), int(buf[3]), host, int(port)}
	t := gotabulate.Create([][]interface{}{row})
	t.SetHeaders([]string{"VER", "CMD", "RSV", "ATYP", "ADDR", "PORT"})
	fmt.Println(t.Render("grid"))

	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

func transport(src, dst net.Conn) {
	defer dst.Close()
	buf := make([]byte, 2048)
	for {
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}
