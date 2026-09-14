```python
#!/usr/bin/env python3
"""
Authorized Web Pentest Assistant — Streamlit

Tests actifs mais NON destructifs :
- HTTPS / TLS
- Security headers
- CORS
- Cookies
- Méthodes HTTP annoncées
- Découverte de routes via HTML / robots.txt
- Recherche de fichiers publics sensibles
- Test de réflexion de paramètres avec un marqueur inoffensif

Ce programme n'effectue PAS :
- de brute-force
- de bypass d'authentification
- d'injection SQL
- d'exécution de commandes
- d'upload de fichiers
- de suppression/modification de données
- de scan de ports
- de fuzzing agressif

Utilise-le uniquement sur des systèmes que tu possèdes ou pour lesquels
tu as une autorisation explicite.
"""

import json
import re
import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
import streamlit as st


TIMEOUT = 8
MAX_ENDPOINTS = 40
MAX_BODY_SAMPLE = 500

USER_AGENT = "Authorized-Pentest-Assistant/1.0"
HEADERS = {"User-Agent": USER_AGENT}


SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "Force HTTPS et réduit les attaques de downgrade.",
    "Content-Security-Policy":
        "Limite les sources de contenu et réduit l'impact de certains XSS.",
    "X-Frame-Options":
        "Réduit les risques de clickjacking.",
    "X-Content-Type-Options":
        "Empêche certains MIME sniffing.",
    "Referrer-Policy":
        "Réduit les fuites d'informations via le Referer.",
    "Permissions-Policy":
        "Contrôle certaines fonctionnalités du navigateur.",
}


COMMON_PUBLIC_FILES = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".git/HEAD",
    ".git/config",
    ".env",
    ".env.local",
    ".env.production",
    "backup.zip",
    "backup.sql",
    "phpinfo.php",
]


SECRET_RE = re.compile(
    r"(?i)"
    r"(api[_-]?key|secret|password|token|authorization)"
    r"\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9_\-./+=]{8,})"
)


class LinkParser(HTMLParser):
    """Récupère uniquement les liens <a href=...>."""

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return

        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.append(value)


def normalize_url(value):
    value = value.strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return value.rstrip("/")


def same_origin(url_a, url_b):
    a = urlparse(url_a)
    b = urlparse(url_b)

    port_a = a.port or (443 if a.scheme == "https" else 80)
    port_b = b.port or (443 if b.scheme == "https" else 80)

    return (
        a.scheme,
        a.hostname,
        port_a,
    ) == (
        b.scheme,
        b.hostname,
        port_b,
    )


def redact(text):
    """
    Évite d'afficher directement une valeur ressemblant à un secret.
    """

    return SECRET_RE.sub(
        lambda match: f"{match.group(1)}=[REDACTED]",
        text[:MAX_BODY_SAMPLE],
    )


def add_issue(
    result,
    severity,
    title,
    why,
    evidence="",
    remediation="",
):
    result["issues"].append(
        {
            "severity": severity,
            "title": title,
            "why": why,
            "evidence": evidence,
            "remediation": remediation,
        }
    )


def check_tls(url):
    host = urlparse(url).hostname

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, 443),
            timeout=TIMEOUT,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host,
            ) as secure_socket:

                cert = secure_socket.getpeercert()

                expires = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)

                days_left = (
                    expires - datetime.now(timezone.utc)
                ).days

                cipher = secure_socket.cipher()

                return {
                    "ok": True,
                    "tls_version": secure_socket.version(),
                    "cipher": cipher[0] if cipher else None,
                    "certificate_days_left": days_left,
                }

    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
        }


def check_http_to_https(url):
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {
            "checked": False,
            "detail": "La cible a été fournie en HTTP.",
        }

    http_url = urlunparse(
        (
            "http",
            parsed.netloc,
            parsed.path or "/",
            "",
            "",
            "",
        )
    )

    try:
        response = requests.get(
            http_url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        location = response.headers.get(
            "Location",
            "",
        )

        return {
            "redirect": (
                response.status_code in (301, 302, 307, 308)
                and location.lower().startswith("https://")
            ),
            "status": response.status_code,
            "location": location,
        }

    except requests.RequestException as exc:
        return {
            "redirect": None,
            "error": type(exc).__name__,
        }


def check_options(url):
    try:
        response = requests.options(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        return {
            "status": response.status_code,
            "allow": response.headers.get("Allow", ""),
            "cors": response.headers.get(
                "Access-Control-Allow-Origin",
                "",
            ),
            "methods": response.headers.get(
                "Access-Control-Allow-Methods",
                "",
            ),
        }

    except requests.RequestException as exc:
        return {
            "error": type(exc).__name__,
        }


def check_headers(response, result):
    existing = {
        name.lower()
        for name in response.headers
    }

    missing = [
        header
        for header in SECURITY_HEADERS
        if header.lower() not in existing
    ]

    result["headers"] = dict(response.headers)

    if missing:
        add_issue(
            result,
            "medium",
            f"{len(missing)} security header(s) missing",
            (
                "Ces en-têtes renforcent la sécurité côté navigateur. "
                "Leur absence ne signifie pas automatiquement qu'une "
                "vulnérabilité exploitable existe."
            ),
            ", ".join(missing),
            (
                "Configurer les headers au niveau du serveur web, "
                "reverse proxy ou framework."
            ),
        )

    acao = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    acac = response.headers.get(
        "Access-Control-Allow-Credentials"
    )

    if acao == "*":
        add_issue(
            result,
            "review",
            "CORS permissif",
            (
                "Access-Control-Allow-Origin: * permet à des origines "
                "web arbitraires de faire des requêtes lisibles par "
                "le navigateur. Le risque réel dépend surtout de "
                "l'authentification et des données exposées par l'API."
            ),
            (
                f"Access-Control-Allow-Origin: {acao}; "
                f"credentials={acac or 'absent'}"
            ),
            (
                "Pour une API sensible, utiliser une liste stricte "
                "d'origines autorisées."
            ),
        )

    elif acao and acac and acac.lower() == "true":
        add_issue(
            result,
            "review",
            "CORS avec credentials",
            (
                "Les requêtes cross-origin avec credentials doivent "
                "être limitées à des origines de confiance."
            ),
            f"Origin={acao}; credentials=true",
            (
                "Vérifier que seules des origines précises et "
                "nécessaires sont autorisées."
            ),
        )


def check_cookies(response, result):
    problems = []

    for cookie in response.cookies:
        raw = str(cookie)
        flags = []

        if not cookie.secure:
            flags.append("Secure absent")

        if "HttpOnly" not in raw:
            flags.append("HttpOnly absent")

        if "SameSite" not in raw:
            flags.append("SameSite absent")

        if flags:
            problems.append(
                {
                    "cookie": cookie.name,
                    "flags": flags,
                }
            )

    if problems:
        add_issue(
            result,
            "medium",
            "Cookie(s) à vérifier",
            (
                "Des flags faibles peuvent augmenter l'impact de "
                "certaines attaques XSS, CSRF ou interception réseau, "
                "selon l'architecture."
            ),
            str(problems),
            (
                "Pour les cookies de session, utiliser notamment "
                "Secure, HttpOnly et une politique SameSite adaptée."
            ),
        )


def fetch_public_file(base_url, path):
    url = urljoin(
        base_url + "/",
        path,
    )

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        if response.status_code == 200 and response.content:
            return {
                "path": path,
                "status": response.status_code,
                "content_type": response.headers.get(
                    "Content-Type",
                    "",
                ),
                "length": len(response.content),
                "sample": redact(response.text),
            }

    except requests.RequestException:
        pass

    return None


def discover_endpoints(base_url, response):
    """
    Découverte limitée :
    - page HTML initiale
    - robots.txt
    - même origine uniquement
    """

    endpoints = {
        urljoin(base_url, "/")
    }

    parser = LinkParser()

    if "text/html" in response.headers.get(
        "Content-Type",
        "",
    ):
        try:
            parser.feed(response.text[:200000])

            for href in parser.links:
                candidate = urljoin(
                    base_url,
                    href,
                )

                if not same_origin(
                    base_url,
                    candidate,
                ):
                    continue

                parsed = urlparse(candidate)

                normalized = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path or "/",
                        "",
                        parsed.query,
                        "",
                    )
                )

                endpoints.add(normalized)

        except Exception:
            pass

    robots = fetch_public_file(
        base_url,
        "robots.txt",
    )

    if robots:
        for line in robots["sample"].splitlines():
            match = re.match(
                r"(?i)\s*(?:Allow|Disallow):\s*(\S+)",
                line,
            )

            if match:
                endpoints.add(
                    urljoin(
                        base_url,
                        match.group(1),
                    )
                )

    return sorted(endpoints)[:MAX_ENDPOINTS]


def reflection_smoke_test(url):
    """
    Test GET uniquement.

    Remplace un paramètre existant par un marqueur inoffensif et vérifie
    simplement si ce marqueur réapparaît dans la réponse.

    Une réflexion n'est PAS automatiquement une XSS.
    """

    parsed = urlparse(url)

    query = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    if not query:
        return None

    marker = "PENTEST_MARKER_7f31"

    first_parameter = next(iter(query))

    query[first_parameter] = [marker]

    test_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urlencode(query, doseq=True),
            "",
        )
    )

    try:
        response = requests.get(
            test_url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        return {
            "url": test_url,
            "reflected": marker in response.text,
            "content_type": response.headers.get(
                "Content-Type",
                "",
            ),
        }

    except requests.RequestException:
        return None


def scan(target, progress=None):
    base_url = normalize_url(target)

    result = {
        "target": base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "issues": [],
        "discovered_endpoints": [],
        "public_files": [],
        "checks": {},
    }

    def update(message):
        if progress:
            progress(message)

    update("Connexion…")

    try:
        response = requests.get(
            base_url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
        )

    except requests.RequestException as exc:
        result["error"] = (
            f"Connexion impossible : {type(exc).__name__}"
        )
        return result

    result["checks"]["http_status"] = response.status_code
    result["checks"]["final_url"] = response.url

    update("Analyse TLS…")

    tls = check_tls(base_url)

    result["checks"]["tls"] = tls

    if not tls.get("ok"):
        add_issue(
            result,
            "high",
            "Échec de la vérification TLS",
            (
                "Un problème TLS peut entraîner des erreurs de confiance "
                "ou exposer les communications à des risques "
                "d'interception."
            ),
            str(tls),
            "Corriger la configuration du certificat et de HTTPS.",
        )

    redirect = check_http_to_https(base_url)

    result["checks"]["http_to_https"] = redirect

    if redirect.get("redirect") is False:
        add_issue(
            result,
            "high",
            "HTTP n'est pas redirigé vers HTTPS",
            (
                "Un utilisateur peut commencer sa connexion sans "
                "chiffrement avant d'atteindre HTTPS."
            ),
            str(redirect),
            (
                "Rediriger HTTP vers HTTPS puis envisager HSTS "
                "après validation."
            ),
        )

    update("Analyse des headers et CORS…")

    check_headers(
        response,
        result,
    )

    update("Analyse des cookies…")

    check_cookies(
        response,
        result,
    )

    update("Analyse des méthodes HTTP…")

    result["checks"]["options"] = check_options(
        base_url
    )

    update("Recherche de fichiers publics…")

    for path in COMMON_PUBLIC_FILES:
        found = fetch_public_file(
            base_url,
            path,
        )

        if not found:
            continue

        result["public_files"].append(found)

        sensitive_paths = {
            ".env",
            ".env.local",
            ".env.production",
            ".git/config",
            ".git/HEAD",
            "backup.zip",
            "backup.sql",
        }

        if path in sensitive_paths:
            add_issue(
                result,
                "critical",
                f"Fichier potentiellement sensible public : {path}",
                (
                    "Un fichier de configuration, dépôt Git ou backup "
                    "accessible publiquement peut révéler des secrets, "
                    "identifiants ou informations internes."
                ),
                (
                    f"HTTP 200, {found['length']} octets, "
                    f"{found['content_type']}"
                ),
                (
                    "Retirer le fichier du répertoire public et "
                    "révoquer/renouveler tout secret éventuellement exposé."
                ),
            )

    update("Découverte des routes…")

    endpoints = discover_endpoints(
        base_url,
        response,
    )

    result["discovered_endpoints"] = endpoints

    update("Tests de réflexion des paramètres…")

    reflections = []

    for endpoint in endpoints:
        test = reflection_smoke_test(endpoint)

        if not test:
            continue

        reflections.append(test)

        if test["reflected"]:
            add_issue(
                result,
                "review",
                "Paramètre réfléchi dans la réponse",
                (
                    "Une valeur fournie dans l'URL réapparaît dans "
                    "la réponse. Cela ne prouve PAS une XSS : le "
                    "contexte HTML/JS et l'encodage de sortie doivent "
                    "être vérifiés."
                ),
                test["url"],
                (
                    "Vérifier le contexte de réflexion et appliquer "
                    "un encodage de sortie approprié."
                ),
            )

    result["checks"]["reflection_smoke_tests"] = reflections

    return result


SEVERITY_SCORE = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "review": 1,
}


def calculate_score(result):
    return sum(
        SEVERITY_SCORE.get(
            issue["severity"],
            0,
        )
        for issue in result["issues"]
    )


st.set_page_config(
    page_title="Authorized Web Pentest",
    page_icon="🛡️",
    layout="wide",
)

st.title(
    "🛡️ Authorized Web Pentest Assistant"
)

st.caption(
    "Analyse active mais non destructive. "
    "Utilise uniquement cet outil sur des systèmes autorisés."
)

st.info(
    "Le scanner cherche des chemins d'attaque plausibles et explique "
    "leur importance. Il ne tente pas de prendre le contrôle du site."
)

target = st.text_input(
    "URL à tester",
    placeholder="https://monsite.fr",
)

if st.button(
    "🚀 Lancer le pentest",
    type="primary",
):

    if not target.strip():
        st.warning(
            "Indique une URL."
        )

    else:

        status = st.empty()

        with st.spinner(
            "Analyse en cours…"
        ):

            result = scan(
                target,
                progress=lambda message:
                    status.write("⏳ " + message),
            )

        status.empty()

        if result.get("error"):
            st.error(
                result["error"]
            )

        else:

            risk_score = calculate_score(
                result
            )

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Score indicatif",
                risk_score,
            )

            col2.metric(
                "Problèmes",
                len(result["issues"]),
            )

            col3.metric(
                "Routes découvertes",
                len(result["discovered_endpoints"]),
            )

            if not result["issues"]:

                st.success(
                    "Aucun problème détecté par les tests effectués. "
                    "Cela ne garantit pas l'absence de vulnérabilité."
                )

            else:

                priority = {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "review": 3,
                }

                for issue in sorted(
                    result["issues"],
                    key=lambda item:
                        priority.get(
                            item["severity"],
                            99,
                        ),
                ):

                    icon = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "review": "⚪",
                    }.get(
                        issue["severity"],
                        "⚪",
                    )

                    with st.expander(
                        f"{icon} "
                        f"{issue['severity'].upper()} — "
                        f"{issue['title']}"
                    ):

                        st.markdown(
                            "**Pourquoi ?** "
                            + issue["why"]
                        )

                        if issue["evidence"]:
                            st.code(
                                issue["evidence"]
                            )

                        st.markdown(
                            "**Correction :** "
                            + issue["remediation"]
                        )

            with st.expander(
                "🌐 Routes découvertes"
            ):
                for endpoint in result[
                    "discovered_endpoints"
                ]:
                    st.write(
                        endpoint
                    )

            with st.expander(
                "📁 Fichiers publics détectés"
            ):
                st.json(
                    result["public_files"]
                )

            with st.expander(
                "🔬 Résultats techniques"
            ):
                st.json(
                    result["checks"]
                )

            st.download_button(
                "⬇️ Télécharger le rapport JSON",
                data=json.dumps(
                    result,
                    ensure_ascii=False,
                    indent=2,
                ),
                file_name="pentest_report.json",
                mime="application/json",
            )
```

