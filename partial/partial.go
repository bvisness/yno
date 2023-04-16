package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		panic(err)
	}

	conn.Write([]byte("POST / HTTP/1.1\r\nHost: localhost:9000\r\nContent-Length: 100\r\n\r\n"))
	fmt.Println("sent!")
	var c chan struct{}
	<-c
}
