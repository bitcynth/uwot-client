package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
)

var rootServer = flag.String("server", "uwot.cynthia.re:43443", "uwot server")

func main() {
	flag.Parse()

	conf := &tls.Config{}

	conn, err := tls.Dial("tcp", *rootServer, conf)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer conn.Close()

	n, err := conn.Write([]byte(flag.Arg(0) + "\r\n"))
	if err != nil {
		log.Fatal(n, err)
		return
	}

	resp := ""
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
			return
		}
		resp += string(buf[:n])
	}

	fmt.Println(resp)
}
