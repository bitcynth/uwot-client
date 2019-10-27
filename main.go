package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
)

// Trusted EV OIDs, to request an OID to be added, contact: me@cynthia.re
var evOids = []asn1.ObjectIdentifier{
	getOid("2.16.840.1.114412.2.1"),
	getOid("1.3.6.1.4.1.6334.1.100.1"),
	getOid("2.16.840.1.113733.1.7.23.6"),
}

var rootServer = flag.String("server", "uwot.cynthia.re:43443", "uwot server")

func getOid(strrep string) asn1.ObjectIdentifier {
	parts := strings.Split(strrep, ".")
	parts2 := make([]int, len(parts))
	for i, part := range parts {
		parts2[i], _ = strconv.Atoi(part)
	}
	return parts2
}

func main() {
	flag.Parse()

	conf := &tls.Config{}

	conn, err := tls.Dial("tcp", *rootServer, conf)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer conn.Close()

	isEV := false
	state := conn.ConnectionState()
	var cert *x509.Certificate
	for _, v := range state.PeerCertificates {
		if !v.IsCA {
			cert = v
		}
	}
	for _, v := range cert.PolicyIdentifiers {
		for _, oid := range evOids {
			if v.Equal(oid) {
				isEV = true
			}
		}
	}

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

	if isEV && len(cert.Subject.Organization) > 0 && len(cert.Subject.Country) > 0 {
		fmt.Printf("\033[32mVerified by: %s (%s)\033[0m\n", cert.Subject.Organization[0], cert.Subject.Country[0])
	}
}
