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
		fmt.Println("🔍 Domaine détecté, lancement de la reconnaissance sur les sous-domaines avec subfinder...")

		subdomains, err := recon.RunSubfinder(cfg.Domain)
		if err != nil || len(subdomains) == 0 {
			log.Fatalf("❌ Aucun sous-domaine trouvé pour %s : %v", cfg.Domain, err)
		}
		fmt.Printf("✅ %d sous-domaines trouvés.\n", len(subdomains))

		var allUrls []string

		for _, sub := range subdomains {
			fmt.Printf("🔎 Analyse de : %s\n", sub)

			gauUrls, _ := recon.RunGau(sub)
			waybackUrls, _ := recon.RunWaybackurls(sub)
			paramUrls, _ := recon.RunParamSpider(sub)

			merged := recon.MergeAndDeduplicate(gauUrls, waybackUrls, paramUrls)
			allUrls = append(allUrls, merged...)
		}

		if len(allUrls) == 0 {
			log.Fatalf("⚠️ Aucune URL récupérée sur les sous-domaines.")
		}

		fuzzedUrls := recon.InjectFuzzInUrls(allUrls)

		tmpFile := "fuzzed-subdomains.txt"
		err = os.WriteFile(tmpFile, []byte(strings.Join(fuzzedUrls, "\n")), 0644)
		if err != nil {
			log.Fatalf("❌ Erreur écriture fichier : %v", err)
		}

		cfg.URLList = tmpFile
		fmt.Printf("🚀 %d URLs fuzzables extraites depuis les sous-domaines.\n", len(fuzzedUrls))
	}

	if cfg.URL == "" && cfg.URLList == "" && cfg.Domain != "" && cfg.URLList == "" {
		fmt.Println("🔍 Aucune URL extraite via subfinder, fallback sur domaine principal.")

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
