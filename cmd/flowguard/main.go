package main

import (
	"FlowGuard/pkg/config"
	"fmt"
)

func main() {
	conf, err := config.LoadConfig("config.yaml")
	if err != nil {
		panic(err)
	}
	fmt.Println(conf.Forwarding)
}
