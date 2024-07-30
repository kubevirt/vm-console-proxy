package main

import (
	"log"

	"kubevirt.io/vm-console-proxy/pkg/console"
)

func main() {
	err := console.Run()
	if err != nil {
		log.Fatal(err)
	}
}
