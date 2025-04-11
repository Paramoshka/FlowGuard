package main

import (
	"FlowGuard/pkg/config"
	"FlowGuard/pkg/eBPF"
	"log"
	"sync"
)

func main() {
	// Загружаем конфигурацию
	conf, err := config.LoadConfig("/app/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if conf != nil {
		log.Printf("Config loaded successfully")
	}

	// Создаем WaitGroup для синхронизации goroutine
	var wg sync.WaitGroup

	// Инициализируем blocker
	blocker, err := eBPF.New(conf)
	if err != nil {
		log.Fatalf("Failed to create blocker eBPF program: %v", err)
	}
	defer blocker.Close()

	// Инициализируем forwarder
	forwarder, err := eBPF.NewForwarder(conf)
	if err != nil {
		log.Fatalf("Failed to create forwarder eBPF program: %v", err)
	}
	defer forwarder.Close()

	// Добавляем 2 задачи в WaitGroup (по одной на blocker и forwarder)
	wg.Add(2)

	// Запускаем blocker в отдельной goroutine
	go func() {
		defer wg.Done() // Уменьшаем счетчик WaitGroup при завершении
		if err := blocker.ServeTraffic(); err != nil {
			log.Printf("Blocker ServeTraffic failed: %v", err)
		}
	}()

	// Запускаем forwarder в отдельной goroutine
	go func() {
		defer wg.Done() // Уменьшаем счетчик WaitGroup при завершении
		if err := forwarder.ServeTraffic(); err != nil {
			log.Printf("Forwarder ServeTraffic failed: %v", err)
		}
	}()

	// Ждем завершения обеих goroutine
	wg.Wait()
	log.Println("Main: All eBPF programs have stopped.")
}
