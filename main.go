package main

import (
	"api-fuzzer/config"
	"api-fuzzer/fuzz"
	"fmt"
)

func main() {
	cfg := config.ParseArgs()

	fmt.Println("🎯 Fuzzing:", cfg.URL)
	fmt.Println("📦 Payload category:", cfg.Category)
	if cfg.Wordlist != "" {
		fmt.Println("📃 Using custom wordlist:", cfg.Wordlist)
	}

	fuzz.StartFuzzing(cfg)
}
