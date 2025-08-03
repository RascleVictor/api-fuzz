# API Fuzzer - Go

Un outil puissant et extensible de fuzzing API écrit en Go, conçu pour détecter automatiquement des vulnérabilités (XSS, LFI, RCE, IDOR...) sur vos endpoints.

---

## 🚀 Fonctionnalités

- Supporte plusieurs méthodes HTTP (GET, POST, PUT, etc.)
- Injection intelligente de payloads dans les paramètres d'URL, les headers, ou le corps JSON
- Reconnaissance automatique des endpoints avec intégration de `gau` (et bientôt `waybackurls`, `paramspider`)
- Fuzzing multi-threads pour une rapidité optimale
- Support des encodages variés (plain, url, base64...)
- Personnalisation complète via wordlists, headers, cookies, authentification
- Facile à intégrer dans une pipeline CI/CD
- Sortie claire et détaillée pour faciliter l’analyse

---

## 📥 Installation

Vous devez avoir Go installé (>=1.18) et les outils suivants pour la reconnaissance (optionnels mais recommandés) :

- [gau](https://github.com/lc/gau)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)

Clonez le repo :

```bash
git clone https://github.com/tonpseudo/api-fuzz.git
cd api-fuzzer
go build -o api-fuzzer
