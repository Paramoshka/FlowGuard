package main

import (
	"FlowGuard/pkg/eBPF"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Аргументы командной строки
	eBPF.ShowPackets()
	waitForExit()

}

// Ожидаем завершения программы с помощью сигнала
func waitForExit() {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
	fmt.Println("\nExiting...")
}
