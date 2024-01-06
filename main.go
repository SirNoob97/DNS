package main

import (
	"fmt"
	"net"

  "github.com/SirNoob97/DNS/dns"
)

func main() {
	fmt.Println("DNS Server Started")
	packetConn, err := net.ListenPacket("udp", ":1053")
	if err != nil {
		panic(err)
	}
	defer packetConn.Close()
	for {
		buff := make([]byte, 512)
		bytesRead, addr, err := packetConn.ReadFrom(buff)
		if err != nil {
      fmt.Printf("Read error from: %s", addr.String())
      continue
		}

    go dns.HandlePacket(packetConn, addr, buff[:bytesRead])
	}
}
