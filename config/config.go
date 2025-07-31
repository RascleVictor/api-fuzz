package config

import (
	"flag"
	"strings"
)

type Config struct {
	URL         string
	Method      string
	Category    string
	Encodings   string
	RawBody     string
	Headers     string
	ContentType string
	Wordlist    string
	Threads     int
	URLList     string
}

func ParseArgs() Config {
	url := flag.String("url", "", "URL de l'endpoint API à tester")
	method := flag.String("method", "GET", "Méthode HTTP (GET, POST, PUT, etc.)")
	category := flag.String("category", "XSS", "Catégorie de payloads")
	encodings := flag.String("encodings", "plain", "Encodages à utiliser (plain,url,base64,...)")
	rawBody := flag.String("body", "", "Corps JSON brut à modifier (utiliser FUZZ pour injection)")
	headers := flag.String("headers", "", "Headers HTTP au format JSON (utiliser FUZZ pour injection)")
	wordlist := flag.String("wordlist", "", "Chemin vers une wordlist personnalisée")
	threads := flag.Int("threads", 10, "Nombre de threads (goroutines) pour le fuzzing concurrent")
	urlList := flag.String("urllist", "", "Chemin vers un fichier contenant une liste d’URLs à fuzz (1 par ligne)")

	flag.Parse()

	contentType := flag.String("contenttype", "application/json", "Type de contenu à envoyer (application/json, multipart/form-data, application/x-www-form-urlencoded)")

	return Config{
		URL:         *url,
		Method:      strings.ToUpper(*method),
		Category:    *category,
		Encodings:   *encodings,
		RawBody:     *rawBody,
		Headers:     *headers,
		ContentType: *contentType,
		Wordlist:    *wordlist,
		Threads:     *threads,
		URLList:     *urlList,
	}
}
