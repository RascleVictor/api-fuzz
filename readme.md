# API Fuzzer - Go

Un outil puissant et extensible de fuzzing API écrit en Go, conçu pour détecter automatiquement des vulnérabilités (XSS, LFI, RCE, IDOR...) sur vos endpoints.

---

## 🚀 Fonctionnalités

- Supporte plusieurs méthodes HTTP (GET, POST, PUT, etc.)
- Injection intelligente de payloads dans les paramètres d'URL, les headers, ou le corps JSON
- Reconnaissance automatique des endpoints et sous-domaines avec intégration de plusieurs outils :
    - `subfinder` pour la découverte des sous-domaines
    - `gau` (Get All URLs)
    - `waybackurls`
    - `ParamSpider`
    - **`getJS` pour extraire automatiquement les endpoints depuis les fichiers JavaScript**
- Fuzzing multi-threads pour une rapidité optimale
- Support des encodages variés (plain, url, base64...)
- Personnalisation complète via wordlists, headers, cookies, authentification
- Facile à intégrer dans une pipeline CI/CD
- Sortie claire et détaillée pour faciliter l’analyse

---

## 📥 Installation

Vous devez avoir Go installé (>=1.18) et les outils suivants pour la reconnaissance (optionnels mais recommandés) :

- [subfinder](https://github.com/projectdiscovery/subfinder) — découverte des sous-domaines
- [gau](https://github.com/lc/gau) — récupération d’URLs archivées
- [waybackurls](https://github.com/tomnomnom/waybackurls) — récupération d’URLs issues de la Wayback Machine
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) — extraction de paramètres d’URL
- [getJS](https://github.com/003random/getJS) — extraction automatique des endpoints dans les fichiers JavaScript

Clonez le repo :

```bash
git clone https://github.com/tonpseudo/api-fuzzer.git
cd api-fuzzer
go build -o api-fuzzer
