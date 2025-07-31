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
	if rawHeaders == nil {
		rawHeaders = make(map[string]string)
	}

	// ✅ AJOUT cookies + auth
	if cfg.Cookies != "" {
		rawHeaders["Cookie"] = cfg.Cookies
	}
	if cfg.Auth != "" {
		rawHeaders["Authorization"] = cfg.Auth
	}

	var targets []string

	if cfg.URLList != "" {
		content, err := os.ReadFile(cfg.URLList)
		if err != nil {
			fmt.Println("❌ Erreur lecture fichier URL list:", err)
			return
		}
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
		}
	} else if cfg.URL != "" {
		targets = append(targets, cfg.URL)
	} else {
		fmt.Println("❌ Vous devez fournir soit -url soit -urllist")
		return
	}

	// 📏 Baseline pour chaque URL
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, targetURL := range targets {
		baselineURL := strings.Replace(targetURL, "FUZZ", "", -1)

		var baselineBody map[string]interface{}
		if cfg.RawBody != "" {
			bodyStr := strings.Replace(cfg.RawBody, "FUZZ", "", -1)
			if err := json.Unmarshal([]byte(bodyStr), &baselineBody); err != nil {
				fmt.Println("❌ Erreur parsing baseline body:", err)
				baselineBody = nil
			}
		}

		baselineHeaders := make(map[string]string)
		for k, v := range rawHeaders {
			baselineHeaders[k] = strings.Replace(v, "FUZZ", "", -1)
		}

		fmt.Printf("📏 Baseline pour %s\n", targetURL)
		baselineStatus, baselineResp := utils.SendRequest(cfg.Method, baselineURL, baselineBody, baselineHeaders)
		utils.SetBaseline(baselineResp)
		fmt.Printf("🧬 Baseline enregistrée (%d chars, status %d)\n", len(baselineResp), baselineStatus)

		// Fuzzing
		for _, payload := range allPayloads {
			wg.Add(1)
			sem <- struct{}{}

			go func(u, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				finalURL := strings.Replace(u, "FUZZ", p, -1)

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

				// Détection point d'injection
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
					fmt.Printf("🔥 Possible vuln! Reason: %s\n", reason)
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

			}(targetURL, payload)
		}
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
