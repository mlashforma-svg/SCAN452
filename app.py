#!/usr/bin/env python3
"""
app.py — Interface web cliquable pour le scanner de sécurité passif.

Installation :
    pip install streamlit requests --break-system-packages

Lancement local :
    streamlit run app.py
    -> ouvre automatiquement http://localhost:8501

Déploiement en ligne (gratuit, le plus simple) :
    1. Mets ce fichier + security_scanner.py dans un repo GitHub
    2. Va sur https://share.streamlit.io (Streamlit Community Cloud)
    3. Connecte ton repo GitHub, choisis app.py comme fichier principal
    4. Déploie -> tu obtiens une URL publique type https://tonapp.streamlit.app

⚠️ Hostinger en hébergement mutualisé classique ne fait pas tourner d'app Python
en continu (seulement PHP). Si tu veux héberger toi-même, il te faut soit
Streamlit Cloud (gratuit, le plus simple), soit un VPS (Hostinger en propose,
ou Railway/Render qui ont un plan gratuit).
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st

TIMEOUT = 8
USER_AGENT = "Mozilla/5.0 (compatible; AuditBot/1.0; +security-audit)"
HEADERS = {"User-Agent": USER_AGENT}

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
    "wp-config.php.bak", "wp-config.php~", "config.php.bak", ".DS_Store",
    "backup.zip", "backup.sql", "phpinfo.php", "composer.json",
    "package.json", ".htpasswd", "admin/", "wp-admin/", "server-status",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Force HTTPS (protège contre downgrade attack)",
    "Content-Security-Policy": "Limite les scripts pouvant s'exécuter (protège contre XSS)",
    "X-Frame-Options": "Empêche le clickjacking",
    "X-Content-Type-Options": "Empêche le navigateur de mal interpréter les fichiers",
    "Referrer-Policy": "Contrôle les infos envoyées à d'autres sites",
    "Permissions-Policy": "Restreint caméra/micro/géoloc par défaut",
}


def normalize_url(domain: str) -> str:
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    return domain.rstrip("/")


def check_https_redirect(domain: str) -> dict:
    http_url = "http://" + urlparse(normalize_url(domain)).netloc
    try:
        r = requests.get(http_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
        redirected = r.status_code in (301, 302, 307, 308) and "https://" in r.headers.get("Location", "")
        return {"ok": redirected, "detail": f"Statut HTTP: {r.status_code}"}
    except requests.RequestException as e:
        return {"ok": None, "detail": f"Non vérifiable ({e.__class__.__name__})"}


def check_ssl_cert(domain: str) -> dict:
    netloc = urlparse(normalize_url(domain)).netloc
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((netloc, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=netloc) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                return {"ok": days_left > 14, "detail": f"Certificat expire dans {days_left} jours"}
    except Exception as e:
        return {"ok": False, "detail": f"Erreur SSL: {e.__class__.__name__}"}


def check_security_headers(response) -> list:
    return [{"header": h, "why": why} for h, why in SECURITY_HEADERS.items() if h not in response.headers]


def check_cors(response) -> dict:
    acao = response.headers.get("Access-Control-Allow-Origin")
    if acao == "*":
        return {"ok": False, "detail": "CORS ouvert à tous les domaines (Access-Control-Allow-Origin: *)"}
    return {"ok": True, "detail": acao or "Pas de CORS large détecté"}


def check_cookies(response) -> list:
    issues = []
    for cookie in response.cookies:
        flags = []
        if not cookie.secure:
            flags.append("pas de flag Secure")
        raw = str(cookie)
        if "HttpOnly" not in raw:
            flags.append("pas de flag HttpOnly")
        if "SameSite" not in raw:
            flags.append("pas de SameSite")
        if flags:
            issues.append({"cookie": cookie.name, "issues": flags})
    return issues


def check_sensitive_paths(base_url: str) -> list:
    found = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url + "/", path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                found.append({"path": path, "status": r.status_code, "snippet": r.text[:150].replace("\n", " ")})
        except requests.RequestException:
            continue
    return found


def check_directory_listing(base_url: str) -> bool:
    try:
        r = requests.get(base_url + "/wp-content/uploads/", headers=HEADERS, timeout=TIMEOUT)
        return "Index of" in r.text
    except requests.RequestException:
        return False


def check_server_disclosure(response) -> dict:
    server = response.headers.get("Server", "")
    powered_by = response.headers.get("X-Powered-By", "")
    disclosed = bool(re.search(r"\d", server)) or bool(powered_by)
    return {"ok": not disclosed, "server": server, "powered_by": powered_by}


def scan_domain(domain: str, progress_cb=None) -> dict:
    base_url = normalize_url(domain)
    result = {"domain": domain, "scanned_at": datetime.now(timezone.utc).isoformat(), "issues": []}

    try:
        resp = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException as e:
        result["error"] = f"Site injoignable : {e.__class__.__name__}"
        return result

    if progress_cb: progress_cb("Vérification HTTPS...")
    https_check = check_https_redirect(domain)
    if https_check["ok"] is False:
        result["issues"].append({"severity": "haute", "type": "Pas de redirection HTTPS forcée", "detail": https_check["detail"]})

    if progress_cb: progress_cb("Vérification certificat SSL...")
    ssl_check = check_ssl_cert(domain)
    if not ssl_check["ok"]:
        result["issues"].append({"severity": "haute", "type": "Problème certificat SSL", "detail": ssl_check["detail"]})

    if progress_cb: progress_cb("Vérification en-têtes de sécurité...")
    missing_headers = check_security_headers(resp)
    if missing_headers:
        result["issues"].append({"severity": "moyenne", "type": f"{len(missing_headers)} en-têtes de sécurité manquants",
                                  "detail": ", ".join(h["header"] for h in missing_headers)})

    if progress_cb: progress_cb("Vérification CORS...")
    cors_check = check_cors(resp)
    if not cors_check["ok"]:
        result["issues"].append({"severity": "haute", "type": "CORS mal configuré", "detail": cors_check["detail"]})

    if progress_cb: progress_cb("Vérification cookies...")
    cookie_issues = check_cookies(resp)
    if cookie_issues:
        result["issues"].append({"severity": "moyenne", "type": f"{len(cookie_issues)} cookie(s) mal sécurisé(s)", "detail": str(cookie_issues)})

    if progress_cb: progress_cb("Recherche de fichiers sensibles exposés...")
    exposed = check_sensitive_paths(base_url)
    if exposed:
        result["issues"].append({"severity": "CRITIQUE", "type": f"{len(exposed)} fichier(s)/chemin(s) sensible(s) accessibles publiquement",
                                  "detail": ", ".join(f["path"] for f in exposed), "raw": exposed})

    if progress_cb: progress_cb("Vérification listing de répertoire...")
    if check_directory_listing(base_url):
        result["issues"].append({"severity": "moyenne", "type": "Listing de répertoire activé", "detail": "/wp-content/uploads/ liste les fichiers"})

    if progress_cb: progress_cb("Vérification divulgation serveur...")
    server_check = check_server_disclosure(resp)
    if not server_check["ok"]:
        result["issues"].append({"severity": "basse", "type": "Version serveur/techno divulguée",
                                  "detail": f"Server: {server_check['server']} | X-Powered-By: {server_check['powered_by']}"})

    return result


def severity_score(issues: list) -> int:
    weights = {"CRITIQUE": 10, "haute": 5, "moyenne": 2, "basse": 1}
    return sum(weights.get(i["severity"], 0) for i in issues)


def generate_pitch_teaser(result: dict, sender_name: str) -> str:
    if result.get("error") or not result["issues"]:
        return ""
    nb_critique = sum(1 for i in result["issues"] if i["severity"] == "CRITIQUE")
    nb_haute = sum(1 for i in result["issues"] if i["severity"] == "haute")
    nb_total = len(result["issues"])
    urgency = "des failles critiques" if nb_critique else ("des failles importantes" if nb_haute else "plusieurs points d'amélioration")

    return f"""Objet : Audit sécurité rapide de {result['domain']} — {nb_total} point(s) identifié(s)

Bonjour,

En parcourant votre site {result['domain']}, j'ai repéré {urgency} au niveau de la
configuration technique (en-têtes de sécurité, exposition de fichiers, ou configuration serveur —
je reste volontairement vague ici pour ne pas exposer publiquement le détail).

Ce type de faille est souvent invisible pour un visiteur classique mais parfaitement repérable
par n'importe quel scanner automatisé — ce qui inclut, malheureusement, les personnes mal intentionnées.

Je propose un audit de sécurité complet avec :
- Rapport détaillé de chaque point (ce que j'ai trouvé + comment le corriger)
- Priorisation par niveau de risque
- Accompagnement à la correction si besoin

Je reste dispo pour en discuter par téléphone si vous voulez que je vous détaille ce que j'ai vu.

Cordialement,
{sender_name}
"""


SEVERITY_COLOR = {"CRITIQUE": "🔴", "haute": "🟠", "moyenne": "🟡", "basse": "🔵"}

# ---------------------- INTERFACE ----------------------

st.set_page_config(page_title="Scanner sécurité", page_icon="🔍", layout="centered")
st.title("🔍 Scanner de sécurité passif")
st.caption("Vérifications 100% passives (headers HTTP, fichiers publics, SSL) — aucune exploitation, aucune intrusion.")

sender_name = st.text_input("Ton nom / ta société (pour le message de prospection)", value="JBM Services / Lashforma")
domains_input = st.text_area("Domaines à scanner (un par ligne)", placeholder="exemple.fr\nautresite.com", height=100)

if st.button("🚀 Lancer le scan", type="primary"):
    domains = [d.strip() for d in domains_input.splitlines() if d.strip()]
    if not domains:
        st.warning("Ajoute au moins un domaine.")
    else:
        for domain in domains:
            st.divider()
            st.subheader(domain)
            status = st.empty()
            with st.spinner(f"Scan de {domain}..."):
                result = scan_domain(domain, progress_cb=lambda m: status.write(f"⏳ {m}"))
            status.empty()

            if result.get("error"):
                st.error(result["error"])
                continue

            score = severity_score(result["issues"])
            if not result["issues"]:
                st.success("Aucun problème détecté sur les points vérifiés. ✅")
                continue

            st.metric("Score de risque", score, help="CRITIQUE=10, haute=5, moyenne=2, basse=1 par problème")

            for issue in sorted(result["issues"], key=lambda x: -severity_score([x])):
                icon = SEVERITY_COLOR.get(issue["severity"], "⚪")
                with st.expander(f"{icon} [{issue['severity'].upper()}] {issue['type']}"):
                    st.write(issue["detail"])

            pitch = generate_pitch_teaser(result, sender_name)
            st.text_area(f"📩 Message de prospection — {domain}", value=pitch, height=280, key=f"pitch_{domain}")
            st.download_button(
                f"⬇️ Télécharger le message ({domain})",
                data=pitch,
                file_name=f"pitch_{re.sub(r'[^ -zA-Z0-9.-]', '_', domain)}.txt",
                key=f"dl_{domain}",
            )
