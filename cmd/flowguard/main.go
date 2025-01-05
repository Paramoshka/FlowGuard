package main

import (
	"FlowGuard/pkg/eBPF"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Аргументы командной строки
	iface := flag.String("iface", "", "Network interface to attach the eBPF program (e.g., eth0)")
	cmd := flag.String("cmd", "load", "Command to execute: load, stats, block")
	//ip := flag.String("ip", "", "IP address to block (used with 'block' command)")
	flag.Parse()
	// Проверяем, что интерфейс указан
	if *iface == "" {
		log.Fatalf("Error: network interface must be specified with -iface")
	}

	switch *cmd {
	case "load":
		// Загрузка и привязка eBPF программы
		coll, prog, err := eBPF.LoadStats(*iface)
		fmt.Println(prog.FD())
		// Вывод статистики
		err = eBPF.ShowStats(coll)
		if err != nil {
			log.Fatalf("Failed to retrieve statistics: %v", err)
		}
		// Ожидаем завершения с помощью сигнала (Ctrl+C)
		waitForExit()
	case "stats":

	default:
		log.Fatalf("Unknown command: %s. Supported commands: load, stats, block", *cmd)
	}
}

// Ожидаем завершения программы с помощью сигнала
func waitForExit() {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
	fmt.Println("\nExiting...")
}
