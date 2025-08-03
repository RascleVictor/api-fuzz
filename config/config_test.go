package config

import (
	"flag"
	"os"
	"testing"
)

func TestParseArgsDefault(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cmd"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	config := ParseArgs()

	if config.Method != "GET" {
		t.Errorf("Méthode par défaut incorrecte : attendu GET, obtenu %s", config.Method)
	}
}
