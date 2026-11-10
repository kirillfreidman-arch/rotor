// Command whoami is a tiny HTTP server that replies with the client's IP.
// It plays the role of "the target website" in the local demo, so you can
// see which exit IP each request left from.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8000", "address to listen on")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintln(w, ip)
	})
	log.Printf("whoami listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
