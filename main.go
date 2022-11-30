package main

import (
	"log"

	"github.com/akrejcir/vm-console-proxy/pkg/console"
)

func main() {
	err := console.Run()
	if err != nil {
		log.Fatal(err)
	}
}
