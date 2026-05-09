# Custom WAF — Web Application Firewall

Projet réalisé dans le cadre du cours de cybersécurité — ENSAM Casablanca 2026
Professeur : Pr. Mouaad Mohy-eddine

## Description

WAF custom développé en Python, agissant comme reverse proxy devant OWASP Juice Shop.
Il inspecte le trafic HTTP et bloque les attaques SQLi et XSS en temps réel.

## Architecture

Kali (attaquant) → WAF Python :8080 → Juice Shop :3000

## Fichiers

| Fichier | Description |
|---|---|
| waf.py | Proxy WAF + Dashboard (port 8080 / 9000) |
| rules.json | Règles de détection SQLi et XSS |
| block.html | Page 403 personnalisée |

## Prérequis

- Python 3.x
- OWASP Juice Shop sur le port 3000 via Docker

## Lancement

    python3 waf.py

## Accès

- WAF Proxy : http://IP:8080
- Dashboard  : http://IP:9000

## Règles de détection

| ID | Type | Description |
|---|---|---|
| SQLi-001 | SQLi | OR bypass |
| SQLi-002 | SQLi | UNION SELECT |
| SQLi-004 | SQLi | DROP TABLE |
| SQLi-005 | SQLi | Stacked queries |
| XSS-001 | XSS | Script tag |
| XSS-002 | XSS | Event handler |
| XSS-003 | XSS | Javascript protocol |
| XSS-004 | XSS | Iframe injection |
| XSS-005 | XSS | SVG onload |
