package payloads

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func GetAllPayloads(category string, encodings string, wordlistPath string) []string {
	if wordlistPath != "" {
		return loadCustomWordlist(wordlistPath)
	}

	var base []string
	switch category {
	case "XSS":
		base = XSSPayloads()
	case "SQLi":
		base = SQLiPayloads()
	case "Traversal":
		base = TraversalPayloads()
	case "IDOR":
		base = IDORPayloads()
	default:
		return nil
	}

	all := []string{}
	encodingList := strings.Split(encodings, ",")
	for _, payload := range base {
		for _, enc := range encodingList {
			all = append(all, EncodePayload(payload, enc))
		}
	}
	return all
}

func loadCustomWordlist(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("❌ Impossible d'ouvrir la wordlist %s: %v\n", path, err)
		return []string{}
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			payloads = append(payloads, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("❌ Erreur lecture wordlist : %v\n", err)
	}
	return payloads
}
