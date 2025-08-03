package utils

import (
	"fmt"
	"math"
	"strings"
)

var knownErrorPatterns = []string{
	"syntax error", "unexpected", "mysql_fetch", "SQL syntax", "unterminated",
	"NullReferenceException", "Traceback (most recent call last)",
	"Stacktrace", "Warning:", "Fatal error", "eval()", "System.IndexOutOfRangeException",
	"org.springframework", "You have an error in your SQL syntax", "MongoError",
}

var baselineLength = -1

func IsResponseSuspicious(statusCode int, responseBody, injectedPayload string) (bool, string) {
	score := 0
	reasons := []string{}
	lower := strings.ToLower(responseBody)

	if statusCode >= 500 {
		score += 30
		reasons = append(reasons, "Status Code 5xx")
	} else if statusCode >= 400 {
		score += 10
		reasons = append(reasons, "Status Code 4xx")
	}

	if injectedPayload != "" && strings.Contains(responseBody, injectedPayload) {
		score += 30
		reasons = append(reasons, "Payload reflété (possible XSS/SSTI)")
	}

	for _, pattern := range knownErrorPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			score += 40
			reasons = append(reasons, "Erreur détectée: "+pattern)
			break
		}
	}

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

func SetBaseline(responseBody string) {
	baselineLength = len(responseBody)
}

// Helper itoa sans strconv
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
