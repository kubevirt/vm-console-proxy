package main

import (
	"log"

	"github.com/kubevirt/vm-console-proxy/pkg/console"
)

func main() {
	err := console.Run()
	if err != nil {
		log.Fatal(err)
	}
}
