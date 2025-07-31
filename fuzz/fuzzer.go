package fuzz

import (
	"api-fuzzer/config"
	"api-fuzzer/payloads"
	"api-fuzzer/types"
	"api-fuzzer/utils"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

func StartFuzzing(cfg config.Config) {
	allPayloads := payloads.GetAllPayloads(cfg.Category, cfg.Encodings, cfg.Wordlist)

	// 🔄 Décodage des headers JSON en brut
	var rawHeaders map[string]string
	if cfg.Headers != "" {
		if err := json.Unmarshal([]byte(cfg.Headers), &rawHeaders); err != nil {
			fmt.Println("❌ Erreur parsing headers:", err)
			rawHeaders = nil
		}
	}

	// 📏 Enregistrement de la baseline (réponse sans payload)
	baselineURL := strings.Replace(cfg.URL, "FUZZ", "", -1)

	var baselineBody map[string]interface{}
	if cfg.RawBody != "" {
		bodyStr := strings.Replace(cfg.RawBody, "FUZZ", "", -1)
		if err := json.Unmarshal([]byte(bodyStr), &baselineBody); err != nil {
			fmt.Println("❌ Erreur parsing baseline body:", err)
			baselineBody = nil
		}
	}

	baselineHeaders := make(map[string]string)
	if rawHeaders != nil {
		for k, v := range rawHeaders {
			baselineHeaders[k] = strings.Replace(v, "FUZZ", "", -1)
		}
	}

	fmt.Println("📏 Enregistrement de la baseline...")
	baselineStatus, baselineResp := utils.SendRequest(cfg.Method, baselineURL, baselineBody, baselineHeaders)
	utils.SetBaseline(baselineResp)
	fmt.Printf("🧬 Baseline enregistrée (%d chars, status %d)\n\n", len(baselineResp), baselineStatus)

	// 🔁 Lancement du fuzzing
	// Concurrency control
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, payload := range allPayloads {
		wg.Add(1)
		sem <- struct{}{} // bloque si trop de threads

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			finalURL := strings.Replace(cfg.URL, "FUZZ", p, -1)

			var requestBody map[string]interface{}
			if cfg.RawBody != "" {
				bodyStr := strings.Replace(cfg.RawBody, "FUZZ", p, -1)
				if err := json.Unmarshal([]byte(bodyStr), &requestBody); err != nil {
					fmt.Println("❌ Erreur parsing body:", err)
					return
				}
			}

			headers := make(map[string]string)
			for k, v := range rawHeaders {
				headers[k] = strings.Replace(v, "FUZZ", p, -1)
			}

			// Détection de point d’injection
			injectionPoint := "URL"
			if cfg.RawBody != "" && strings.Contains(cfg.RawBody, "FUZZ") {
				injectionPoint = "Body"
			}
			for k, v := range rawHeaders {
				if strings.Contains(v, "FUZZ") {
					injectionPoint = fmt.Sprintf("Header:%s", k)
					break
				}
			}

			fmt.Printf("🚀 [%s] %s\n", cfg.Method, finalURL)

			status, body := utils.SendRequest(cfg.Method, finalURL, requestBody, headers)
			suspicious, reason := utils.IsResponseSuspicious(status, body, p)

			if suspicious {
				fmt.Printf("🔥 Possible vulnerability detected! Reason: %s\n", reason)
				fmt.Println("🧪 Payload:", p)
				fmt.Println("📍 Injection:", injectionPoint)
				fmt.Println("📡 Response:", body)
				fmt.Println("--------------------------------------------------")

				result := types.FuzzResult{
					Method:    cfg.Method,
					URL:       finalURL,
					Payload:   p,
					Reason:    reason,
					Response:  body,
					Injection: injectionPoint,
				}
				saveResult(result)
			}

			fmt.Printf("🔎 [%d] %s\n\n", status, body)

		}(payload)
	}

	wg.Wait()
}

func saveResult(res types.FuzzResult) {
	file, err := os.OpenFile("results.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("❌ Erreur ouverture fichier résultats :", err)
		return
	}
	defer file.Close()

	data, _ := json.Marshal(res)
	file.Write(append(data, '\n'))
}
