package main

import (
	"log"

	"kubevirt.io/vm-console-access/pkg/console"
)

func main() {
	err := console.Run()
	if err != nil {
		log.Fatal(err)
	}
}
