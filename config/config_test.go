package config

import (
	"flag"
	"testing"
)

func TestParseArgsDefault(t *testing.T) {

	args := []string{"cmd"}
	oldArgs := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ExitOnError)
	defer func() { flag.CommandLine = oldArgs }()

	config := ParseArgs()

	if config.Method != "GET" {
		t.Errorf("Méthode par défaut incorrecte: attendu GET, obtenu %s", config.Method)
	}
}
