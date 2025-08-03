package recon

import (
	"bufio"
	"net/url"
	"os/exec"
	"strings"
)

func RunGau(domain string) ([]string, error) {
	cmd := exec.Command("gau", domain)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var urls []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}
	cmd.Wait()
	return urls, nil
}

func RunWaybackurls(domain string) ([]string, error) {
	cmd := exec.Command("waybackurls", domain)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var urls []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}
	cmd.Wait()
	return urls, nil
}

func RunParamSpider(domain string) ([]string, error) {
	cmd := exec.Command("paramspider", "-d", domain, "--exclude", "png,jpg,jpeg,gif,css,svg,woff,woff2")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var urls []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") && strings.Contains(line, "=") {
			urls = append(urls, line)
		}
	}
	cmd.Wait()
	return urls, nil
}

func MergeAndDeduplicate(lists ...[]string) []string {
	unique := make(map[string]struct{})
	for _, list := range lists {
		for _, u := range list {
			unique[u] = struct{}{}
		}
	}
	var merged []string
	for u := range unique {
		merged = append(merged, u)
	}
	return merged
}

func InjectFuzzInUrls(urls []string) []string {
	var fuzzed []string

	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := parsed.Query()
		for param := range q {
			q.Set(param, "FUZZ")
		}
		parsed.RawQuery = q.Encode()
		fuzzed = append(fuzzed, parsed.String())
	}

	return fuzzed
}
