package main

import (
	"FlowGuard/pkg/config"
	"FlowGuard/pkg/eBPF"
	"log"
)

func main() {
	conf, err := config.LoadConfig("config.yaml")
	if err != nil {
		panic(err)
	}
	if conf != nil {
		log.Printf("Config loaded successfully")
	}

	blocker, err := eBPF.New(conf)
	if err != nil {
		log.Fatalf("Failed create blocker eBPF programm: %v", err)
	}
	defer blocker.Close()

	blocker.ServeTraffic()

}
