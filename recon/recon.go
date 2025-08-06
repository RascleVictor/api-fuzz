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

func RunSubfinder(domain string) ([]string, error) {
	cmd := exec.Command("subfinder", "-silent", "-d", domain)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var subs []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subs = append(subs, line)
		}
	}
	cmd.Wait()
	return subs, nil
}

func RunGetJS(target string) ([]string, error) {
	cmd := exec.Command("getJS", "-u", target, "-silent")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var results []string
	seen := make(map[string]bool)
	for _, line := range lines {
		if line != "" && !seen[line] {
			results = append(results, line)
			seen[line] = true
		}
	}
	return results, nil
}

func RunNaabu(domains []string) ([]string, error) {
	cmd := exec.Command("naabu", "-silent", "-host", "-")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		for _, domain := range domains {
			_, _ = stdin.Write([]byte(domain + "\n"))
		}
	}()

	var results []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			results = append(results, line)
		}
	}

	err = cmd.Wait()
	return results, err
}
