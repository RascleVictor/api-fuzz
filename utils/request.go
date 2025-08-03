package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func SendRequest(method, target string, body map[string]interface{}, headers map[string]string) (int, string) {
	var req *http.Request
	var err error

	method = strings.ToUpper(method)

	switch method {
	case "GET", "DELETE":
		params := url.Values{}
		for k, v := range body {
			params.Add(k, fmt.Sprintf("%v", v))
		}
		fullURL := target
		if strings.Contains(target, "?") {
			fullURL += "&" + params.Encode()
		} else {
			fullURL += "?" + params.Encode()
		}
		req, err = http.NewRequest(method, fullURL, nil)
	default:
		jsonData, _ := json.Marshal(body)
		req, err = http.NewRequest(method, target, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
	}

	if err != nil {
		fmt.Println("❌ Erreur création requête :", err)
		return 0, ""
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("❌ Erreur d'envoi :", err)
		return 0, ""
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)

	return resp.StatusCode, buf.String()
}
