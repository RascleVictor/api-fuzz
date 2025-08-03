package main

import (
	"api-fuzzer/config"
	"api-fuzzer/fuzz"
	"api-fuzzer/recon"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	cfg := config.ParseArgs()

	if cfg.URL == "" && cfg.URLList == "" && cfg.Domain != "" {
		fmt.Println("🔍 Domaine détecté, lancement de la reconnaissance avec gau + waybackurls + paramspider...")

		gauUrls, err := recon.RunGau(cfg.Domain)
		if err != nil {
			log.Fatalf("❌ Erreur gau : %v", err)
		}

		waybackUrls, err := recon.RunWaybackurls(cfg.Domain)
		if err != nil {
			log.Fatalf("❌ Erreur waybackurls : %v", err)
		}

		paramspiderUrls, err := recon.RunParamSpider(cfg.Domain)
		if err != nil {
			log.Fatalf("❌ Erreur paramspider : %v", err)
		}

		allUrls := recon.MergeAndDeduplicate(gauUrls, waybackUrls, paramspiderUrls)

		if len(allUrls) == 0 {
			log.Fatalf("⚠️ Aucune URL récupérée pour %s", cfg.Domain)
		}

		fuzzedUrls := recon.InjectFuzzInUrls(allUrls)

		tmpFile := "fuzzed-urls.txt"
		err = os.WriteFile(tmpFile, []byte(strings.Join(fuzzedUrls, "\n")), 0644)
		if err != nil {
			log.Fatalf("❌ Erreur écriture fichier d'URL : %v", err)
		}

		cfg.URLList = tmpFile
		fmt.Printf("✅ %d URLs fuzzées prêtes pour le fuzzing.\n", len(fuzzedUrls))
	}

	fmt.Println("🎯 Fuzzing:")
	if cfg.URL != "" {
		fmt.Println("URL unique:", cfg.URL)
	} else if cfg.URLList != "" {
		fmt.Println("Liste d'URLs:", cfg.URLList)
	} else {
		log.Fatal("❌ Vous devez fournir soit -url, -urllist, ou -domain")
	}

	fmt.Println("📦 Payload category:", cfg.Category)
	if cfg.Wordlist != "" {
		fmt.Println("📃 Utilisation de la wordlist personnalisée:", cfg.Wordlist)
	}

	fuzz.StartFuzzing(cfg)
}
