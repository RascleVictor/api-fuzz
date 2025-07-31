package utils

import (
	"fmt"
	"math"
	"strings"
)

// Liste d'erreurs classiques à détecter dans les réponses
var knownErrorPatterns = []string{
	"syntax error", "unexpected", "mysql_fetch", "SQL syntax", "unterminated",
	"NullReferenceException", "Traceback (most recent call last)",
	"Stacktrace", "Warning:", "Fatal error", "eval()", "System.IndexOutOfRangeException",
	"org.springframework", "You have an error in your SQL syntax", "MongoError",
}

var baselineLength = -1 // longueur de la baseline (réponse sans injection)

// Calcule si une réponse semble vulnérable selon plusieurs critères
func IsResponseSuspicious(statusCode int, responseBody, injectedPayload string) (bool, string) {
	score := 0
	reasons := []string{}
	lower := strings.ToLower(responseBody)

	// 1. Status code
	if statusCode >= 500 {
		score += 30
		reasons = append(reasons, "Status Code 5xx")
	} else if statusCode >= 400 {
		score += 10
		reasons = append(reasons, "Status Code 4xx")
	}

	// 2. Payload reflété
	if injectedPayload != "" && strings.Contains(responseBody, injectedPayload) {
		score += 30
		reasons = append(reasons, "Payload reflété (possible XSS/SSTI)")
	}

	// 3. Erreurs connues
	for _, pattern := range knownErrorPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			score += 40
			reasons = append(reasons, "Erreur détectée: "+pattern)
			break
		}
	}

	// 4. Écart de longueur (si baseline connue)
	if baselineLength > 0 {
		diff := math.Abs(float64(len(responseBody) - baselineLength))
		if diff > 100 {
			score += 20
			reasons = append(reasons, "Changement significatif de taille dans la réponse")
		}
	}

	if score >= 40 {
		return true, "💥 Score: " + itoa(score) + " - " + strings.Join(reasons, " | ")
	}

	return false, ""
}

// Enregistre la longueur de la réponse de base (sans payload) pour la comparer ensuite
func SetBaseline(responseBody string) {
	baselineLength = len(responseBody)
}

// Helper itoa sans strconv
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
