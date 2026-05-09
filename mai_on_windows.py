#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     MAI - AI ASSISTANT v3.0                                  ║
║         Segurança Defensiva • TI • Finanças • Festas • Chat Livre            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

COMPATIBILIDADE: Windows, Linux, macOS
PYTHON: 3.9+

INSTALAÇÃO RÁPIDA:
    python mai.py --install

USO:
    python mai.py chat                    # Modo chat livre (principal)
    python mai.py scan https://site.com   # Scan de segurança web
    python mai.py scan arquivo.py -t code # Análise de código
    python mai.py dns exemplo.com         # Análise de DNS/WHOIS
    python mai.py headers https://site.com# Análise de headers HTTP
    python mai.py news                    # Notícias de segurança
    python mai.py protect --target linux  # Recomendações de hardening
    python mai.py cve CVE-2024-1234       # Consultar CVE
    python mai.py config --init           # Configurar API keys
    python mai.py history                 # Histórico de scans
"""

import os
import sys
import json
import re
import sqlite3
import logging
import hashlib
import socket
import ipaddress
import subprocess
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════════════════════
# DETECÇÃO DE PLATAFORMA
# ═══════════════════════════════════════════════════════════════════════════

IS_WINDOWS = sys.platform == "win32"
IS_LINUX   = sys.platform == "linux"
IS_MAC     = sys.platform == "darwin"

# ═══════════════════════════════════════════════════════════════════════════
# GERENCIAMENTO DE DEPENDÊNCIAS
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_PACKAGES = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "requests>=2.31.0",
    "beautifulsoup4>=4.12.0",
    "pydantic>=2.0.0",
    "python-dotenv>=1.0.0",
    "groq>=0.4.0",
    "dnspython>=2.4.0",
    "python-whois>=0.9.0",
    "cryptography>=41.0.0",
    "feedparser>=6.0.0",
]

def check_and_install(package: str) -> bool:
    name = package.split(">=")[0].split("==")[0]
    import_name = name.replace("-", "_")
    import_map = {
        "python_dotenv": "dotenv",
        "python_whois":  "whois",
        "beautifulsoup4":"bs4",
    }
    import_name = import_map.get(import_name, import_name)
    try:
        __import__(import_name)
        return True
    except ImportError:
        pass

    # No Windows não usamos --break-system-packages
    pip_flags_list = (
        [["--break-system-packages"], []]
        if not IS_WINDOWS
        else [[]]
    )
    for flags in pip_flags_list:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", package] + flags,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return True
        except Exception:
            continue
    return False

def install_all(verbose: bool = True):
    if verbose:
        print("⏳ Verificando e instalando dependências...")
    failed = []
    for pkg in REQUIRED_PACKAGES:
        name = pkg.split(">=")[0]
        if verbose:
            sys.stdout.write(f"  → {name}... ")
            sys.stdout.flush()
        ok = check_and_install(pkg)
        if verbose:
            print("✅" if ok else "❌")
        if not ok:
            failed.append(name)
    if failed and verbose:
        print(f"\n⚠️  Falhou: {', '.join(failed)}")
        print("   Tente: pip install " + " ".join(failed))
    elif verbose:
        print("\n✅ Todas as dependências instaladas!")

# Importação silenciosa
try:
    import typer
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.markdown import Markdown
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich import box
    from dotenv import load_dotenv
except ImportError:
    install_all()
    try:
        import typer
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        from rich.markdown import Markdown
        from rich.prompt import Prompt, Confirm
        from rich.syntax import Syntax
        from rich.tree import Tree
        from rich import box
        from dotenv import load_dotenv
    except ImportError:
        print("❌ Execute: python mai.py install")
        sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

load_dotenv()
MAI_DIR  = Path.home() / ".mai"
DB_PATH  = MAI_DIR / "mai.db"
ENV_FILE = MAI_DIR / ".env"
LOG_FILE = MAI_DIR / "mai.log"
MAI_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger  = logging.getLogger("mai")
console = Console()

BANNER = r"""
███╗   ███╗ █████╗ ██╗
████╗ ████║██╔══██╗██║
██╔████╔██║███████║██║
██║╚██╔╝██║██╔══██║██║
██║ ╚═╝ ██║██║  ██║██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝"""

# ═══════════════════════════════════════════════════════════════════════════
# PROTEÇÃO DE ARQUIVO (cross-platform)
# ═══════════════════════════════════════════════════════════════════════════

def _secure_file(path: Path):
    """Restringe permissões de arquivo de forma cross-platform."""
    if IS_WINDOWS:
        try:
            import subprocess
            # Remove herança de permissões e concede acesso só ao usuário atual
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:F"],
                    capture_output=True, check=False
                )
        except Exception:
            pass
    else:
        try:
            import stat
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

# ═══════════════════════════════════════════════════════════════════════════
# MODELOS DE DADOS
# ═══════════════════════════════════════════════════════════════════════════

class VulnLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    level: VulnLevel
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    references: List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    scan_id: str
    scan_type: str
    target: str
    timestamp: str
    vulnerabilities: List[Vulnerability]
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityNews:
    id: str
    title: str
    description: str
    source: str
    url: str
    published: str
    risk_level: str

# ═══════════════════════════════════════════════════════════════════════════
# BANCO DE DADOS
# ═══════════════════════════════════════════════════════════════════════════

class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init()
        _secure_file(self.db_path)

    def _conn(self):
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                score REAL,
                result_json TEXT,
                status TEXT DEFAULT 'completed'
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                level TEXT,
                cwe TEXT,
                owasp_category TEXT,
                remediation TEXT,
                evidence TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS news (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                source TEXT,
                url TEXT,
                published TEXT,
                risk_level TEXT,
                fetched_at TEXT,
                UNIQUE(url)
            );
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dns_results (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                result_json TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scan_ts  ON scans(timestamp);
            CREATE INDEX IF NOT EXISTS idx_vuln_lvl ON vulnerabilities(level);
            CREATE INDEX IF NOT EXISTS idx_chat_ses ON chat_history(session_id);
            CREATE INDEX IF NOT EXISTS idx_dns_dom  ON dns_results(domain);
        """)
        conn.commit()
        conn.close()

    def save_scan(self, result: ScanResult):
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO scans (id,scan_type,target,timestamp,score,result_json) VALUES (?,?,?,?,?,?)",
            (result.scan_id, result.scan_type, result.target, result.timestamp,
             result.score, json.dumps(asdict(result), default=str))
        )
        conn.commit(); conn.close()

    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        conn = self._conn()
        rows = conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def save_news(self, n: SecurityNews):
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO news (id,title,description,source,url,published,risk_level,fetched_at) VALUES (?,?,?,?,?,?,?,?)",
                (n.id, n.title, n.description, n.source, n.url,
                 n.published, n.risk_level, datetime.now().isoformat())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()

    def get_latest_news(self, risk_level: Optional[str] = None, limit: int = 20) -> List[Dict]:
        conn = self._conn()
        if risk_level:
            rows = conn.execute(
                "SELECT * FROM news WHERE risk_level=? ORDER BY published DESC LIMIT ?",
                (risk_level, limit)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM news ORDER BY published DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def save_message(self, session_id: str, role: str, content: str):
        conn = self._conn()
        conn.execute(
            "INSERT INTO chat_history (session_id,role,content,timestamp) VALUES (?,?,?,?)",
            (session_id, role, content, datetime.now().isoformat())
        )
        conn.commit(); conn.close()

    def get_session_messages(self, session_id: str, limit: int = 50) -> List[Dict]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT role,content FROM chat_history WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit)
        ).fetchall()
        conn.close()
        return list(reversed([dict(r) for r in rows]))

    def save_dns(self, domain: str, result: Dict):
        conn = self._conn()
        rid = hashlib.md5(f"{domain}{datetime.now().isoformat()}".encode()).hexdigest()
        conn.execute(
            "INSERT OR REPLACE INTO dns_results (id,domain,result_json,timestamp) VALUES (?,?,?,?)",
            (rid, domain, json.dumps(result), datetime.now().isoformat())
        )
        conn.commit(); conn.close()

    def get_cache(self, key: str) -> Optional[str]:
        conn = self._conn()
        row = conn.execute(
            "SELECT value, expires_at FROM cache WHERE key=?", (key,)
        ).fetchone()
        conn.close()
        if row:
            if row["expires_at"] > datetime.now().isoformat():
                return row["value"]
        return None

    def set_cache(self, key: str, value: str, ttl_seconds: int = 3600):
        from datetime import timedelta
        expires = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO cache (key,value,expires_at) VALUES (?,?,?)",
            (key, value, expires)
        )
        conn.commit(); conn.close()

# ═══════════════════════════════════════════════════════════════════════════
# SISTEMA PROMPT MAI
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """Você é MAI, uma assistente de IA brasileira especializada em segurança da informação defensiva, TI, finanças e assuntos gerais.

Você fala português do Brasil fluentemente.

Suas especialidades incluem:

🔐 SEGURANÇA DA INFORMAÇÃO (foco defensivo):
- Análise de vulnerabilidades, OWASP Top 10, CVEs
- Hardening de sistemas Linux, Windows Server, containers
- Análise de logs, SIEM, detecção de intrusão (IDS/IPS)
- Criptografia aplicada, PKI, TLS/SSL, hash seguro
- Segurança em nuvem (AWS, GCP, Azure)
- LGPD/GDPR, compliance, gestão de riscos
- Forense digital e resposta a incidentes
- Bug bounty (responsável e ético), pentest com autorização
- CTF e desafios educacionais de segurança

💻 TECNOLOGIA DA INFORMAÇÃO:
- Programação: Python, Bash, JavaScript, Go, Rust, C
- Linux/Unix e Windows: administração, scripting, kernel
- DevOps: Docker, Kubernetes, CI/CD, Terraform
- Redes: TCP/IP, BGP, DNS, firewalls, VPNs
- Banco de dados, APIs REST/GraphQL, microsserviços

💰 FINANÇAS PESSOAIS:
- Investimentos brasileiros: Tesouro Direto, CDBs, FIIs, ações
- Planejamento financeiro, orçamento, reserva de emergência
- Criptomoedas, DeFi (com análise de riscos)

🎉 EVENTOS E ORGANIZAÇÃO:
- Planejamento de festas, casamentos, formaturas
- Orçamento, fornecedores, cronograma, checklists

PERSONALIDADE:
- Direta, técnica e precisa
- Sempre menciona o contexto ético/legal quando relevante (pentest só com autorização, etc.)
- Usa emojis com moderação
- Adapta a linguagem ao nível do usuário
- Quando não sabe, admite honestamente

Responda sempre em português do Brasil, salvo se o usuário usar outro idioma."""

# ═══════════════════════════════════════════════════════════════════════════
# CLIENTE GROQ (IA)
# ═══════════════════════════════════════════════════════════════════════════

class GroqClient:
    MODELS = [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "gemma2-9b-it",
    ]

    def __init__(self):
        self.api_key = self._load_key()
        self.client  = None
        if self.api_key:
            self._init_client()

    def _load_key(self) -> Optional[str]:
        if ENV_FILE.exists():
            load_dotenv(ENV_FILE, override=True)
        return os.getenv("GROQ_API_KEY")

    def _init_client(self):
        try:
            from groq import Groq
            self.client = Groq(api_key=self.api_key)
        except Exception as e:
            logger.error(f"Falha ao inicializar Groq: {e}")

    def is_ready(self) -> bool:
        return self.client is not None

    def chat(self, messages: List[Dict], system: str = SYSTEM_PROMPT,
             max_tokens: int = 4096, temperature: float = 0.7) -> str:
        if not self.client:
            return "❌ GROQ_API_KEY não configurada. Execute: python mai.py config --init"

        full_messages = [{"role": "system", "content": system}] + messages

        for model in self.MODELS:
            try:
                resp = self.client.chat.completions.create(
                    model=model,
                    messages=full_messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    stream=False
                )
                logger.info(f"Chat OK: model={model}, tokens={resp.usage.total_tokens if resp.usage else '?'}")
                return resp.choices[0].message.content
            except Exception as e:
                logger.warning(f"Modelo {model} falhou: {e}")
                continue

        return "❌ Todos os modelos falharam. Verifique sua chave e conexão."

    def stream_chat(self, messages: List[Dict], system: str = SYSTEM_PROMPT,
                    max_tokens: int = 4096, temperature: float = 0.7):
        if not self.client:
            yield "❌ GROQ_API_KEY não configurada. Execute: python mai.py config --init"
            return

        full_messages = [{"role": "system", "content": system}] + messages

        for model in self.MODELS:
            try:
                stream = self.client.chat.completions.create(
                    model=model,
                    messages=full_messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    stream=True
                )
                for chunk in stream:
                    delta = chunk.choices[0].delta.content
                    if delta:
                        yield delta
                return
            except Exception as e:
                logger.warning(f"Streaming model {model} falhou: {e}")
                continue

        yield "\n❌ Erro: todos os modelos falharam."

# ═══════════════════════════════════════════════════════════════════════════
# ANALISADOR DE SEGURANÇA WEB
# ═══════════════════════════════════════════════════════════════════════════

class WebAnalyzer:
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "title": "HSTS ausente",
            "desc": "HTTP Strict Transport Security não configurado. Permite downgrade para HTTP.",
            "level": VulnLevel.HIGH, "owasp": "A02",
            "fix": "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "ref": "https://owasp.org/www-project-secure-headers/"
        },
        "X-Content-Type-Options": {
            "title": "X-Content-Type-Options ausente",
            "desc": "Vulnerável a MIME-type sniffing.",
            "level": VulnLevel.MEDIUM, "owasp": "A05",
            "fix": "Adicione: X-Content-Type-Options: nosniff"
        },
        "X-Frame-Options": {
            "title": "Proteção contra Clickjacking ausente",
            "desc": "Sem X-Frame-Options, a página pode ser embarcada em iframes maliciosos.",
            "level": VulnLevel.MEDIUM, "owasp": "A05",
            "fix": "Adicione: X-Frame-Options: DENY ou SAMEORIGIN"
        },
        "Content-Security-Policy": {
            "title": "Content Security Policy ausente",
            "desc": "Sem CSP, ataques XSS têm superfície de ataque ampliada.",
            "level": VulnLevel.HIGH, "owasp": "A03",
            "fix": "Implemente CSP restritivo. Ex: Content-Security-Policy: default-src 'self'"
        },
        "Referrer-Policy": {
            "title": "Referrer-Policy ausente",
            "desc": "URLs de referência podem vazar para sites externos.",
            "level": VulnLevel.LOW, "owasp": "A05",
            "fix": "Adicione: Referrer-Policy: strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "title": "Permissions-Policy ausente",
            "desc": "Permissões de APIs do browser não restritas.",
            "level": VulnLevel.LOW, "owasp": "A05",
            "fix": "Adicione: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        },
    }

    def analyze_headers(self, headers: Dict[str, str], url: str = "") -> List[Vulnerability]:
        vulns = []
        normalized = {k.title(): v for k, v in headers.items()}

        for header, info in self.SECURITY_HEADERS.items():
            if header not in normalized:
                vid = f"HDR_{hashlib.md5(header.encode()).hexdigest()[:8]}"
                vulns.append(Vulnerability(
                    id=vid, title=info["title"], description=info["desc"],
                    level=info["level"], owasp_category=info["owasp"],
                    remediation=info["fix"],
                    references=info.get("ref", "https://owasp.org").split(",")
                ))

        for leak_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]:
            val = normalized.get(leak_header)
            if val:
                vulns.append(Vulnerability(
                    id=f"LEAK_{hashlib.md5(leak_header.encode()).hexdigest()[:8]}",
                    title=f"Vazamento de versão: {leak_header}",
                    description=f"Header '{leak_header}' expõe informação de tecnologia: {val}",
                    level=VulnLevel.LOW,
                    owasp_category="A05",
                    evidence=f"{leak_header}: {val}",
                    remediation=f"Remova ou genérico o header '{leak_header}' na configuração do servidor."
                ))

        set_cookies = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        if set_cookies:
            cookie_str = set_cookies.lower()
            if "secure" not in cookie_str:
                vulns.append(Vulnerability(
                    id="COOKIE_SECURE",
                    title="Cookie sem flag Secure",
                    description="Cookies podem ser transmitidos em conexões HTTP não criptografadas.",
                    level=VulnLevel.HIGH, owasp_category="A02",
                    remediation="Adicione a flag Secure a todos os cookies de sessão."
                ))
            if "httponly" not in cookie_str:
                vulns.append(Vulnerability(
                    id="COOKIE_HTTPONLY",
                    title="Cookie sem flag HttpOnly",
                    description="Cookies acessíveis via JavaScript — risco de roubo em ataques XSS.",
                    level=VulnLevel.MEDIUM, owasp_category="A07",
                    remediation="Adicione a flag HttpOnly a cookies de sessão."
                ))
            if "samesite" not in cookie_str:
                vulns.append(Vulnerability(
                    id="COOKIE_SAMESITE",
                    title="Cookie sem SameSite",
                    description="Sem SameSite, cookies podem ser enviados em requisições cross-site (CSRF).",
                    level=VulnLevel.MEDIUM, owasp_category="A01",
                    remediation="Adicione SameSite=Strict ou SameSite=Lax aos cookies."
                ))

        return vulns

    def scan(self, url: str) -> ScanResult:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        vulns: List[Vulnerability] = []
        score = 100
        metadata: Dict[str, Any] = {}

        parsed = urlparse(url)

        if parsed.scheme != "https":
            vulns.append(Vulnerability(
                id="NO_HTTPS",
                title="Site sem HTTPS",
                description="Conexão não criptografada. Dados trafegam em texto claro.",
                level=VulnLevel.CRITICAL, owasp_category="A02",
                remediation="Configure SSL/TLS (Let's Encrypt é gratuito) e redirecione HTTP → HTTPS."
            ))
            score -= 20

        try:
            resp = requests.get(
                url, timeout=15, verify=False,
                headers={"User-Agent": "Mozilla/5.0 MAI-SecurityScanner/3.0"},
                allow_redirects=True
            )
            headers = dict(resp.headers)
            metadata["status_code"]    = resp.status_code
            metadata["redirect_chain"] = [r.url for r in resp.history]
            metadata["final_url"]      = resp.url
            metadata["content_type"]   = headers.get("Content-Type", "")
            metadata["server"]         = headers.get("Server", "")

            hdr_vulns = self.analyze_headers(headers, url)
            vulns.extend(hdr_vulns)
            score -= sum({"critical": 15, "high": 8, "medium": 4, "low": 1, "info": 0}.get(v.level.value, 0) for v in hdr_vulns)

            if parsed.scheme == "https":
                try:
                    http_url = url.replace("https://", "http://", 1)
                    r2 = requests.get(http_url, timeout=8, verify=False, allow_redirects=False)
                    if r2.status_code not in (301, 302, 308) or "https" not in r2.headers.get("Location", "").lower():
                        vulns.append(Vulnerability(
                            id="NO_HTTPS_REDIRECT",
                            title="Sem redirecionamento HTTP → HTTPS",
                            description="Acessar o site via HTTP não redireciona para HTTPS automaticamente.",
                            level=VulnLevel.MEDIUM, owasp_category="A02",
                            remediation="Configure redirecionamento 301 de HTTP para HTTPS no servidor."
                        ))
                        score -= 5
                except Exception:
                    pass

            if resp.headers.get("Content-Type", "").startswith("text/html"):
                html = resp.text[:50000]
                if "http://" in html and parsed.scheme == "https":
                    count = html.count("http://")
                    if count > 2:
                        vulns.append(Vulnerability(
                            id="MIXED_CONTENT",
                            title="Possível Mixed Content",
                            description=f"Página HTTPS pode carregar recursos via HTTP ({count} ocorrências).",
                            level=VulnLevel.MEDIUM, owasp_category="A02",
                            remediation="Garanta que todos os recursos sejam carregados via HTTPS."
                        ))
                        score -= 5

            cors = headers.get("Access-Control-Allow-Origin", "")
            if cors == "*":
                vulns.append(Vulnerability(
                    id="CORS_WILDCARD",
                    title="CORS com wildcard (Access-Control-Allow-Origin: *)",
                    description="Qualquer origem pode fazer requisições cross-origin.",
                    level=VulnLevel.MEDIUM, owasp_category="A01",
                    remediation="Restrinja CORS a origens específicas e confiáveis."
                ))
                score -= 5

        except requests.exceptions.SSLError:
            vulns.append(Vulnerability(
                id="SSL_ERROR",
                title="Erro de certificado SSL/TLS",
                description="Certificado SSL inválido, expirado ou auto-assinado.",
                level=VulnLevel.CRITICAL, owasp_category="A02",
                remediation="Renove ou corrija o certificado SSL. Use Let's Encrypt para certificados gratuitos."
            ))
            score -= 25
        except requests.exceptions.ConnectionError:
            vulns.append(Vulnerability(
                id="CONN_ERROR",
                title="Falha na conexão",
                description=f"Não foi possível conectar a {url}.",
                level=VulnLevel.INFO, owasp_category=None,
                remediation="Verifique se o host está online e acessível."
            ))
            score = 0
        except requests.exceptions.Timeout:
            vulns.append(Vulnerability(
                id="TIMEOUT",
                title="Timeout na conexão",
                description="O servidor demorou mais de 15s para responder.",
                level=VulnLevel.INFO, owasp_category=None,
                remediation="Verifique a performance e disponibilidade do servidor."
            ))
            score -= 10
        except Exception as e:
            logger.error(f"Erro ao escanear {url}: {e}")

        score = max(0, min(100, score))
        scan_id = hashlib.md5(f"{url}{datetime.now().isoformat()}".encode()).hexdigest()

        return ScanResult(
            scan_id=scan_id, scan_type="web", target=url,
            timestamp=datetime.now().isoformat(),
            vulnerabilities=vulns, score=score, metadata=metadata
        )


# ═══════════════════════════════════════════════════════════════════════════
# ANALISADOR DE CÓDIGO ESTÁTICO
# ═══════════════════════════════════════════════════════════════════════════

class CodeAnalyzer:
    PATTERNS: Dict[str, Dict] = {
        r"eval\s*\(":
            {"title": "Uso de eval()", "desc": "eval() executa código arbitrário — risco de RCE.", "level": VulnLevel.CRITICAL, "cwe": "CWE-95", "owasp": "A03"},
        r"\bexec\s*\(":
            {"title": "Uso de exec()", "desc": "exec() executa código arbitrário.", "level": VulnLevel.CRITICAL, "cwe": "CWE-95", "owasp": "A03"},
        r"subprocess\.(call|run|Popen).*shell\s*=\s*True":
            {"title": "subprocess com shell=True", "desc": "Permite command injection se entrada do usuário for passada.", "level": VulnLevel.HIGH, "cwe": "CWE-78", "owasp": "A03"},
        r"os\.system\s*\(":
            {"title": "os.system()", "desc": "Risco de command injection. Use subprocess com lista de args.", "level": VulnLevel.HIGH, "cwe": "CWE-78", "owasp": "A03"},
        r"os\.popen\s*\(":
            {"title": "os.popen()", "desc": "Deprecado e vulnerável a command injection.", "level": VulnLevel.HIGH, "cwe": "CWE-78", "owasp": "A03"},
        r"pickle\.loads?\s*\(":
            {"title": "Desserialização pickle insegura", "desc": "pickle pode executar código arbitrário durante desserialização.", "level": VulnLevel.HIGH, "cwe": "CWE-502", "owasp": "A08"},
        r"yaml\.load\s*\([^,)]+\)":
            {"title": "yaml.load() sem Loader seguro", "desc": "yaml.load() sem Loader=yaml.SafeLoader é vulnerável a RCE.", "level": VulnLevel.HIGH, "cwe": "CWE-502", "owasp": "A08"},
        r"(?i)password\s*=\s*['\"][^'\"]{3,}['\"]":
            {"title": "Senha hardcoded", "desc": "Credencial exposta diretamente no código-fonte.", "level": VulnLevel.CRITICAL, "cwe": "CWE-798", "owasp": "A02"},
        r"(?i)secret[\s_-]*key\s*=\s*['\"][^'\"]{3,}['\"]":
            {"title": "Secret Key hardcoded", "desc": "Chave secreta exposta no código.", "level": VulnLevel.CRITICAL, "cwe": "CWE-798", "owasp": "A02"},
        r"(?i)api[\s_-]*key\s*=\s*['\"][^'\"]{5,}['\"]":
            {"title": "API Key hardcoded", "desc": "Chave de API exposta no código.", "level": VulnLevel.CRITICAL, "cwe": "CWE-798", "owasp": "A02"},
        r"(?i)token\s*=\s*['\"][A-Za-z0-9+/]{20,}['\"]":
            {"title": "Token hardcoded", "desc": "Token de autenticação exposto no código.", "level": VulnLevel.CRITICAL, "cwe": "CWE-798", "owasp": "A02"},
        r"\bmd5\s*\(":
            {"title": "Hash MD5 (inseguro)", "desc": "MD5 é criptograficamente quebrado.", "level": VulnLevel.MEDIUM, "cwe": "CWE-328", "owasp": "A02"},
        r"\bsha1\s*\(":
            {"title": "Hash SHA-1 (fraco)", "desc": "SHA-1 é considerado inseguro. Use SHA-256 ou SHA-3.", "level": VulnLevel.LOW, "cwe": "CWE-328", "owasp": "A02"},
        r"DES\b|3DES\b|RC4\b|RC2\b":
            {"title": "Algoritmo de criptografia obsoleto", "desc": "DES/3DES/RC4/RC2 são algoritmos quebrados ou deprecados.", "level": VulnLevel.HIGH, "cwe": "CWE-327", "owasp": "A02"},
        r"execute\s*\(\s*f[\"'].*{":
            {"title": "SQL com f-string (possível SQLi)", "desc": "f-string em query SQL — vulnerável a SQL Injection.", "level": VulnLevel.HIGH, "cwe": "CWE-89", "owasp": "A03"},
        r'execute\s*\(\s*".*\+':
            {"title": "SQL com concatenação (possível SQLi)", "desc": "Concatenação de strings em query SQL — alto risco de SQL Injection.", "level": VulnLevel.CRITICAL, "cwe": "CWE-89", "owasp": "A03"},
        r"DEBUG\s*=\s*True":
            {"title": "DEBUG ativo", "desc": "Modo DEBUG expõe stack traces e informações sensíveis.", "level": VulnLevel.HIGH, "cwe": "CWE-489", "owasp": "A05"},
        r"verify\s*=\s*False":
            {"title": "Verificação SSL desativada", "desc": "verify=False desativa validação de certificado SSL — vulnerável a MITM.", "level": VulnLevel.HIGH, "cwe": "CWE-295", "owasp": "A02"},
    }

    def analyze(self, code: str, filename: str = "código") -> List[Vulnerability]:
        vulns = []
        seen_patterns = set()

        for pattern, info in self.PATTERNS.items():
            try:
                matches = list(re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE))
                if matches and pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    first_match = matches[0]
                    line_num = code[:first_match.start()].count("\n") + 1
                    evidence = f"Linha {line_num}: {code.splitlines()[line_num-1].strip()[:100]}"

                    vid = f"CODE_{hashlib.md5(f'{pattern}{filename}'.encode()).hexdigest()[:8]}"
                    vulns.append(Vulnerability(
                        id=vid,
                        title=info["title"],
                        description=info["desc"],
                        level=info["level"],
                        cwe=info.get("cwe"),
                        owasp_category=info.get("owasp"),
                        remediation=f"Revise o uso de '{pattern}' no arquivo '{filename}'.",
                        evidence=evidence
                    ))
            except re.error:
                continue

        return vulns

    def get_score(self, vulns: List[Vulnerability]) -> float:
        weights = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
        penalty = sum(weights.get(v.level.value, 0) for v in vulns)
        return max(0, 100 - penalty)


# ═══════════════════════════════════════════════════════════════════════════
# ANALISADOR DE DNS / WHOIS
# ═══════════════════════════════════════════════════════════════════════════

class DNSAnalyzer:
    def analyze(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "records": {},
            "security": {},
            "whois": {},
            "issues": []
        }

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = resolver.resolve(domain, rtype)
                    result["records"][rtype] = [str(r) for r in answers]
                except Exception:
                    result["records"][rtype] = []

            txt_records = " ".join(result["records"].get("TXT", []))

            if "v=spf1" in txt_records:
                result["security"]["SPF"] = "✅ Configurado"
            else:
                result["security"]["SPF"] = "❌ Ausente"
                result["issues"].append(("SPF ausente", "Sem registro SPF, domínio pode ser usado em e-mail spoofing.", VulnLevel.HIGH))

            try:
                dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
                dmarc_txt = " ".join([str(r) for r in dmarc])
                if "v=DMARC1" in dmarc_txt:
                    policy = "none"
                    if "p=reject" in dmarc_txt: policy = "reject"
                    elif "p=quarantine" in dmarc_txt: policy = "quarantine"
                    result["security"]["DMARC"] = f"✅ Configurado (policy={policy})"
                    if policy == "none":
                        result["issues"].append(("DMARC com policy=none", "DMARC configurado mas sem ação.", VulnLevel.MEDIUM))
            except Exception:
                result["security"]["DMARC"] = "❌ Ausente"
                result["issues"].append(("DMARC ausente", "Sem DMARC, ataques de spoofing de e-mail são mais fáceis.", VulnLevel.HIGH))

            try:
                resolver.resolve(domain, "DNSKEY")
                result["security"]["DNSSEC"] = "✅ Configurado"
            except Exception:
                result["security"]["DNSSEC"] = "⚠️  Não detectado"
                result["issues"].append(("DNSSEC não detectado", "Sem DNSSEC, respostas DNS podem ser forjadas.", VulnLevel.MEDIUM))

            ns_records = result["records"].get("NS", [])
            if ns_records:
                result["security"]["Nameservers"] = f"✅ {len(ns_records)} NS encontrado(s)"
            else:
                result["security"]["Nameservers"] = "❌ Sem NS registrado"

        except ImportError:
            result["issues"].append(("dnspython não instalado", "Execute: pip install dnspython", VulnLevel.INFO))
        except Exception as e:
            result["issues"].append((f"Erro DNS: {str(e)}", "", VulnLevel.INFO))

        try:
            import whois
            w = whois.whois(domain)
            if w:
                result["whois"] = {
                    "registrar":   str(w.registrar or "N/A"),
                    "created":     str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or "N/A"),
                    "expires":     str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or "N/A"),
                    "country":     str(w.country or "N/A"),
                    "name_servers": [str(ns) for ns in (w.name_servers or [])[:4]],
                }

                if w.expiration_date:
                    exp = w.expiration_date
                    if isinstance(exp, list):
                        exp = exp[0]
                    if hasattr(exp, "date"):
                        from datetime import timedelta
                        days_left = (exp - datetime.now()).days
                        if days_left < 30:
                            result["issues"].append((
                                f"Domínio expira em {days_left} dias!",
                                "Renove o domínio imediatamente.",
                                VulnLevel.CRITICAL
                            ))
                        elif days_left < 90:
                            result["issues"].append((
                                f"Domínio expira em {days_left} dias",
                                "Considere renovar em breve.",
                                VulnLevel.MEDIUM
                            ))
        except ImportError:
            result["whois"]["erro"] = "python-whois não instalado"
        except Exception as e:
            result["whois"]["erro"] = str(e)

        return result


# ═══════════════════════════════════════════════════════════════════════════
# ANALISADOR DE HEADERS HTTP
# ═══════════════════════════════════════════════════════════════════════════

class HeaderAnalyzer:
    def analyze_url(self, url: str) -> Dict[str, Any]:
        import requests
        import urllib3
        urllib3.disable_warnings()

        result = {"url": url, "headers": {}, "score": 100, "issues": [], "good": []}

        try:
            resp = requests.get(
                url, timeout=10, verify=False,
                headers={"User-Agent": "Mozilla/5.0 MAI-HeaderAnalyzer/3.0"}
            )
            result["headers"] = dict(resp.headers)
            result["status"] = resp.status_code

            analyzer = WebAnalyzer()
            vulns = analyzer.analyze_headers(dict(resp.headers), url)
            result["issues"] = vulns

            for v in vulns:
                weights = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
                result["score"] -= weights.get(v.level.value, 0)

            good_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                            "X-Frame-Options", "X-Content-Type-Options",
                            "Referrer-Policy", "Permissions-Policy"]
            normalized = {k.title(): v for k, v in resp.headers.items()}
            for h in good_headers:
                if h in normalized:
                    result["good"].append((h, normalized[h][:80]))

            result["score"] = max(0, min(100, result["score"]))

        except Exception as e:
            result["error"] = str(e)

        return result


# ═══════════════════════════════════════════════════════════════════════════
# AGREGADOR DE NOTÍCIAS
# ═══════════════════════════════════════════════════════════════════════════

class NewsAggregator:
    RSS_FEEDS = {
        "The Hacker News": "https://feeds.thehackernews.com/",
        "Krebs on Security": "https://krebsonsecurity.com/feed/",
        "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
        "Threatpost": "https://threatpost.com/feed/",
    }

    RISK_KEYWORDS = {
        "critical": ["zero-day", "zero day", "critical", "rce", "remote code execution",
                     "ransomware", "worm", "active exploit", "mass exploitation"],
        "high":     ["high", "remote code", "privilege escalation", "data breach",
                     "backdoor", "supply chain", "apt", "nation-state"],
        "medium":   ["medium", "phishing", "vulnerability", "patch tuesday", "update",
                     "social engineering", "credential stuffing"],
        "low":      [],
    }

    def __init__(self):
        self.db = Database()

    def _classify_risk(self, title: str, desc: str) -> str:
        text = f"{title} {desc}".lower()
        for level, keywords in self.RISK_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return level
        return "low"

    def fetch(self) -> List[SecurityNews]:
        all_news = []
        try:
            import feedparser
            for source, url in self.RSS_FEEDS.items():
                try:
                    feed = feedparser.parse(url)
                    for entry in feed.entries[:6]:
                        title = entry.get("title", "")
                        desc  = entry.get("summary", "")[:400]
                        link  = entry.get("link", "")
                        pub   = entry.get("published", datetime.now().isoformat())
                        risk  = self._classify_risk(title, desc)
                        nid   = hashlib.md5(link.encode()).hexdigest()
                        news  = SecurityNews(id=nid, title=title, description=desc,
                                             source=source, url=link, published=pub, risk_level=risk)
                        self.db.save_news(news)
                        all_news.append(news)
                except Exception as e:
                    logger.warning(f"Feed {source} falhou: {e}")
        except ImportError:
            pass

        if not all_news:
            samples = [
                ("CERT.br: Campanha de ransomware mira infraestrutura crítica brasileira", "Grupos APT atacam hospitais e energia.", "CERT.br", "critical"),
                ("CVE-2024: Vulnerabilidade crítica no OpenSSH corrigida", "Atualização urgente recomendada para servidores.", "NVD", "critical"),
                ("ANPD: Novo guia de Relatório de Impacto à Proteção de Dados (RIPD)", "Empresas têm 90 dias para adequação.", "ANPD", "medium"),
                ("Ataques de supply chain crescem 300% em 2024", "Dependências npm e PyPI comprometidas.", "Snyk", "high"),
                ("Microsoft corrige 5 zero-days no Patch Tuesday", "Atualização afeta Windows, Office e Exchange.", "Microsoft", "critical"),
                ("Novo malware Windows mira ambientes corporativos", "Backdoor explora vulnerabilidade no RDP.", "Sysdig", "high"),
                ("Guia OWASP LLM Top 10 atualizado para 2024", "Novos vetores de ataque em IA generativa.", "OWASP", "medium"),
                ("Cloudflare bloqueia maior DDoS da história: 3.8 Tbps", "Ataque durou 65 segundos usando IoT comprometida.", "Cloudflare", "high"),
            ]
            for title, desc, src, risk in samples:
                nid  = hashlib.md5(title.encode()).hexdigest()
                news = SecurityNews(id=nid, title=title, description=desc, source=src,
                                    url=f"https://example.com/{nid}", published=datetime.now().isoformat(),
                                    risk_level=risk)
                self.db.save_news(news)
                all_news.append(news)

        return all_news


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

app      = typer.Typer(help="🤖 MAI v3.0 — Segurança Defensiva • TI • Chat Livre", rich_markup_mode="rich")
ai       = GroqClient()
web_sec  = WebAnalyzer()
code_sec = CodeAnalyzer()
dns_sec  = DNSAnalyzer()
hdr_sec  = HeaderAnalyzer()
news_agg = NewsAggregator()
db       = Database()

def _print_banner():
    platform_info = f"Windows {sys.version.split()[0]}" if IS_WINDOWS else sys.platform
    status = "[green]●[/green] IA Online" if ai.is_ready() else "[red]●[/red] IA Offline (configure API key)"
    console.print(Panel(
        f"[bold cyan]{BANNER}[/bold cyan]\n"
        f"[dim]AI Assistant v3.0 • Segurança Defensiva • TI • Chat Livre[/dim]\n"
        f"[dim]{status} | {platform_info}[/dim]",
        border_style="cyan", padding=(0, 2)
    ))

def _vuln_color(level: str) -> str:
    return {"critical": "bold red", "high": "red", "medium": "yellow",
            "low": "green", "info": "blue"}.get(level.lower(), "white")

def _score_color(score: float) -> str:
    if score >= 80: return "green"
    if score >= 50: return "yellow"
    return "red"

def _score_label(score: float) -> str:
    if score >= 90: return "Excelente"
    if score >= 75: return "Bom"
    if score >= 50: return "Regular"
    if score >= 25: return "Ruim"
    return "Crítico"

def _validate_url(url: str) -> Tuple[bool, str]:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, url
        try:
            ip = socket.gethostbyname(parsed.hostname)
            if ipaddress.ip_address(ip).is_private:
                return False, f"[red]❌ Endereço privado/local não permitido: {ip}[/red]"
        except Exception:
            pass
        return True, url
    except Exception:
        return False, url

# ─────────────────────────────────────────────────────────────────────────
# CHAT
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="💬 Modo chat livre com MAI")
def chat(
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Continuar sessão existente"),
    no_stream: bool = typer.Option(False, "--no-stream", help="Desativar streaming"),
    context: Optional[str] = typer.Option(None, "--context", "-c", help="Contexto inicial"),
):
    _print_banner()

    if not ai.is_ready():
        console.print(Panel(
            "[yellow]⚠️  IA não configurada.[/yellow]\n"
            "Execute primeiro: [cyan]python mai.py config --init[/cyan]\n"
            "Obtenha sua chave GRATUITA em: [link=https://console.groq.com]https://console.groq.com[/link]",
            border_style="yellow"
        ))
        return

    session_id = session or hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:8]
    history: List[Dict] = db.get_session_messages(session_id)

    system = SYSTEM_PROMPT
    if context:
        system += f"\n\nContexto desta sessão: {context}"

    console.print(Panel(
        f"[bold green]Chat iniciado![/bold green] ID: [cyan]{session_id}[/cyan]\n"
        "[dim]Comandos: 'sair' • 'limpar' • 'historico' • 'sessao' • 'ajuda'[/dim]",
        border_style="green"
    ))

    if not history:
        greeting = (
            "Olá! 👋 Sou a **MAI**, assistente de segurança da informação e TI.\n\n"
            "Especialidades:\n"
            "- 🔐 Segurança defensiva, hardening, análise de vulnerabilidades\n"
            "- 💻 Windows, Linux, programação, DevOps, redes\n"
            "- 💰 Finanças e investimentos\n"
            "- 🌍 Chat geral sobre qualquer assunto\n\n"
            "Como posso te ajudar hoje?"
        )
        console.print(Panel(Markdown(greeting), title="[bold cyan]MAI[/bold cyan]", border_style="cyan"))

    while True:
        try:
            user_input = Prompt.ask("\n[bold green]Você[/bold green]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Sessão encerrada. Até logo! 👋[/dim]")
            break

        if not user_input:
            continue

        cmd = user_input.lower().strip()

        if cmd in ("sair", "exit", "quit", "bye", "tchau"):
            console.print("[dim]Até logo! 👋[/dim]")
            break

        if cmd == "limpar":
            history.clear()
            session_id = hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:8]
            console.print(f"[green]Nova sessão: {session_id}[/green]")
            continue

        if cmd == "historico":
            if history:
                for msg in history[-10:]:
                    label = "[bold green]Você[/bold green]" if msg["role"] == "user" else "[bold cyan]MAI[/bold cyan]"
                    console.print(f"{label}: {msg['content'][:100]}...")
            else:
                console.print("[dim]Sem histórico.[/dim]")
            continue

        if cmd == "sessao":
            console.print(f"[cyan]Session ID: {session_id}[/cyan]")
            continue

        if cmd == "ajuda":
            console.print(Panel(
                "**Comandos no chat:**\n"
                "- `sair` / `exit` → encerrar\n"
                "- `limpar` → nova conversa\n"
                "- `historico` → últimas mensagens\n"
                "- `sessao` → ver ID da sessão\n"
                "- `ajuda` → esta ajuda",
                title="[cyan]Ajuda[/cyan]", border_style="cyan"
            ))
            continue

        history.append({"role": "user", "content": user_input})
        db.save_message(session_id, "user", user_input)

        console.print()
        console.print("[bold cyan]MAI[/bold cyan] ", end="")

        if no_stream:
            with console.status("", spinner="dots"):
                response = ai.chat(history, system=system)
            console.print(Markdown(response))
        else:
            full_response = ""
            try:
                for chunk in ai.stream_chat(history, system=system):
                    console.print(chunk, end="", highlight=False)
                    full_response += chunk
                console.print()
                response = full_response
            except Exception as e:
                response = f"❌ Erro: {e}"
                console.print(response)

        history.append({"role": "assistant", "content": response})
        db.save_message(session_id, "assistant", response)

        if len(history) > 40:
            history = history[-40:]

# ─────────────────────────────────────────────────────────────────────────
# SCAN
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="🔍 Scan de segurança (web ou código-fonte)")
def scan(
    target: str = typer.Argument(..., help="URL ou caminho de arquivo"),
    scan_type: str = typer.Option("web", "--type", "-t", help="Tipo: web, code"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    ai_analysis: bool = typer.Option(False, "--ai", help="Análise com IA"),
    output_json: Optional[str] = typer.Option(None, "--json", "-o", help="Salvar resultado em JSON"),
):
    _print_banner()
    result: Optional[ScanResult] = None

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}[/cyan]"),
                  transient=True, console=console) as prog:
        prog.add_task(f"Escaneando {target}...", total=None)

        try:
            if scan_type == "web":
                valid, processed = _validate_url(target)
                if not valid:
                    console.print(f"[red]❌ URL inválida ou host privado: {processed}[/red]")
                    return
                result = web_sec.scan(processed)

            elif scan_type == "code":
                path = Path(target)
                if not path.exists():
                    console.print(f"[red]❌ Arquivo não encontrado: {target}[/red]")
                    return
                code  = path.read_text(errors="replace")
                vulns = code_sec.analyze(code, path.name)
                score = code_sec.get_score(vulns)
                result = ScanResult(
                    scan_id=hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest(),
                    scan_type="code", target=target,
                    timestamp=datetime.now().isoformat(),
                    vulnerabilities=vulns, score=score,
                    metadata={"lines": len(code.splitlines()), "size_bytes": path.stat().st_size}
                )
                db.save_scan(result)
            else:
                console.print(f"[red]❌ Tipo inválido: {scan_type}. Use 'web' ou 'code'.[/red]")
                return
        except Exception as e:
            console.print(f"[red]❌ Erro: {e}[/red]")
            logger.error(f"Scan error: {e}")
            return

    if result is None:
        return

    table = Table(
        title=f"🔐 Scan — {result.target[:60]}",
        show_header=True, show_lines=True, box=box.ROUNDED
    )
    table.add_column("Nível",  width=10)
    table.add_column("ID",     style="dim", width=12)
    table.add_column("Título", width=38)
    table.add_column("OWASP",  style="yellow", width=6)
    table.add_column("CWE",    style="cyan", width=10)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(result.vulnerabilities, key=lambda v: order.get(v.level.value, 5))

    for v in sorted_vulns:
        color = _vuln_color(v.level.value)
        table.add_row(
            f"[{color}]{v.level.value.upper()}[/{color}]",
            v.id[:12], v.title,
            v.owasp_category or "—",
            v.cwe or "—"
        )

    console.print(table)

    sc = result.score
    sc_color = _score_color(sc)
    console.print(f"\n[{sc_color}]🏆 Score: {sc:.0f}/100 — {_score_label(sc)}[/{sc_color}]")
    console.print(f"[blue]🐛 {len(result.vulnerabilities)} vulnerabilidade(s)[/blue]")
    console.print(f"[dim]💾 ID do scan: {result.scan_id[:8]}[/dim]")

    if result.metadata and verbose:
        for k, v in result.metadata.items():
            console.print(f"[dim]   {k}: {v}[/dim]")

    if verbose and result.vulnerabilities:
        console.print("\n[bold]Detalhes:[/bold]")
        for v in sorted_vulns:
            color = _vuln_color(v.level.value)
            content = v.description
            if v.evidence:
                content += f"\n\n[dim]Evidência: {v.evidence}[/dim]"
            if v.remediation:
                content += f"\n\n[green]✔ Remediação:[/green] {v.remediation}"
            if v.references:
                content += f"\n[blue]🔗 Ref:[/blue] {', '.join(v.references[:2])}"
            console.print(Panel(
                content,
                title=f"[{color}]{v.title}[/{color}]",
                border_style=color.split()[-1]
            ))

    if ai_analysis and result.vulnerabilities:
        if not ai.is_ready():
            console.print("[yellow]⚠️  IA não configurada.[/yellow]")
        else:
            console.print("\n[cyan]🤖 Gerando análise com IA...[/cyan]")
            vuln_summary = "\n".join(
                [f"- [{v.level.value.upper()}] {v.title}: {v.description}" for v in sorted_vulns[:10]]
            )
            prompt = (
                f"Analise estas vulnerabilidades encontradas em '{result.target}' (score: {sc:.0f}/100):\n\n"
                f"{vuln_summary}\n\n"
                "Forneça:\n"
                "1. Resumo executivo do nível de risco\n"
                "2. Vulnerabilidades mais críticas e por que\n"
                "3. Plano de remediação priorizado\n"
                "4. Estimativa de esforço para correção"
            )
            console.print("\n[bold cyan]MAI[/bold cyan]")
            for chunk in ai.stream_chat([{"role": "user", "content": prompt}]):
                console.print(chunk, end="", highlight=False)
            console.print()

    if output_json:
        out = Path(output_json)
        out.write_text(json.dumps(asdict(result), indent=2, default=str), encoding="utf-8")
        console.print(f"[green]✅ Resultado salvo em: {output_json}[/green]")

# ─────────────────────────────────────────────────────────────────────────
# DNS
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="🌐 Análise de DNS, SPF, DMARC, DNSSEC e WHOIS")
def dns(
    domain: str = typer.Argument(..., help="Domínio para analisar (ex: exemplo.com)"),
    ai_report: bool = typer.Option(False, "--ai", help="Gerar relatório com IA"),
):
    _print_banner()

    domain = re.sub(r"https?://", "", domain).split("/")[0].strip()

    with console.status(f"[cyan]Consultando DNS para {domain}...[/cyan]"):
        result = dns_sec.analyze(domain)

    db.save_dns(domain, result)

    console.print(f"\n[bold cyan]📋 Registros DNS — {domain}[/bold cyan]")
    for rtype, records in result.get("records", {}).items():
        if records:
            console.print(f"  [yellow]{rtype:6}[/yellow]: {', '.join(records[:3])}")

    console.print(f"\n[bold cyan]🔐 Segurança DNS[/bold cyan]")
    for check, status in result.get("security", {}).items():
        console.print(f"  {check:15}: {status}")

    whois_data = result.get("whois", {})
    if whois_data and "erro" not in whois_data:
        console.print(f"\n[bold cyan]📝 WHOIS[/bold cyan]")
        for k, v in whois_data.items():
            if k != "name_servers":
                console.print(f"  [yellow]{k:14}[/yellow]: {v}")

    issues = result.get("issues", [])
    if issues:
        console.print(f"\n[bold red]⚠️  Problemas Detectados ({len(issues)})[/bold red]")
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Nível",    width=10)
        table.add_column("Problema", width=40)
        table.add_column("Ação",     width=50)
        for title, desc, level in issues:
            color = _vuln_color(level.value if hasattr(level, "value") else str(level))
            table.add_row(
                f"[{color}]{str(level.value if hasattr(level, 'value') else level).upper()}[/{color}]",
                title, desc
            )
        console.print(table)
    else:
        console.print("\n[green]✅ Nenhum problema detectado![/green]")

    if ai_report and ai.is_ready():
        console.print("\n[bold cyan]MAI[/bold cyan]")
        prompt = (
            f"Analise a segurança de DNS do domínio '{domain}':\n"
            f"Segurança: {json.dumps(result.get('security', {}), ensure_ascii=False)}\n"
            f"Problemas: {[(t, d) for t, d, _ in issues]}\n\n"
            "Explique os riscos e forneça instruções para corrigir cada problema."
        )
        for chunk in ai.stream_chat([{"role": "user", "content": prompt}]):
            console.print(chunk, end="", highlight=False)
        console.print()

# ─────────────────────────────────────────────────────────────────────────
# HEADERS
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="📋 Análise de security headers HTTP")
def headers(
    url: str = typer.Argument(..., help="URL para analisar"),
    ai_report: bool = typer.Option(False, "--ai"),
):
    _print_banner()

    valid, url = _validate_url(url)
    if not valid:
        console.print(f"[red]❌ URL inválida: {url}[/red]")
        return

    with console.status(f"[cyan]Analisando headers de {url}...[/cyan]"):
        result = hdr_sec.analyze_url(url)

    if "error" in result:
        console.print(f"[red]❌ Erro: {result['error']}[/red]")
        return

    console.print(f"\n[bold cyan]📋 Todos os Headers ({len(result['headers'])})[/bold cyan]")
    hdr_table = Table(show_header=True, box=box.SIMPLE)
    hdr_table.add_column("Header", style="yellow", width=35)
    hdr_table.add_column("Valor",  width=60)
    for k, v in sorted(result["headers"].items()):
        hdr_table.add_row(k, str(v)[:80])
    console.print(hdr_table)

    if result.get("good"):
        console.print(f"\n[bold green]✅ Security Headers Presentes[/bold green]")
        for h, v in result["good"]:
            console.print(f"  [green]✔[/green] {h}: {v}")

    issues = result.get("issues", [])
    if issues:
        console.print(f"\n[bold red]❌ Security Headers Ausentes/Problemáticos[/bold red]")
        for v in issues:
            color = _vuln_color(v.level.value)
            console.print(f"  [{color}]▶[/{color}] [{v.level.value.upper()}] {v.title}")
            console.print(f"    [dim]{v.remediation}[/dim]")

    sc = result.get("score", 0)
    sc_color = _score_color(sc)
    console.print(f"\n[{sc_color}]🏆 Score: {sc:.0f}/100 — {_score_label(sc)}[/{sc_color}]")

    if ai_report and ai.is_ready():
        console.print("\n[bold cyan]MAI[/bold cyan]")
        missing = [v.title for v in issues]
        good    = [h for h, _ in result.get("good", [])]
        prompt  = (
            f"Analise os headers HTTP de '{url}':\n"
            f"Presentes: {good}\nAusentes/problemáticos: {missing}\nScore: {sc}/100\n\n"
            "Para cada header ausente, forneça:\n"
            "1. Por que é importante\n"
            "2. Configuração recomendada (IIS e Apache/Nginx)\n"
            "3. Impacto de não ter esse header"
        )
        for chunk in ai.stream_chat([{"role": "user", "content": prompt}]):
            console.print(chunk, end="", highlight=False)
        console.print()

# ─────────────────────────────────────────────────────────────────────────
# CVE
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="🔎 Consultar informações sobre um CVE")
def cve(
    cve_id: str = typer.Argument(..., help="ID do CVE (ex: CVE-2024-1234)"),
):
    _print_banner()

    if not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        console.print("[red]❌ Formato inválido. Use: CVE-YYYY-NNNNN[/red]")
        return

    cve_id = cve_id.upper()

    cached = db.get_cache(f"cve:{cve_id}")
    if cached:
        data = json.loads(cached)
        console.print(f"[dim](cache)[/dim]")
    else:
        with console.status(f"[cyan]Consultando NVD para {cve_id}...[/cyan]"):
            try:
                import requests
                resp = requests.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                    timeout=10,
                    headers={"User-Agent": "MAI-CVE-Lookup/3.0"}
                )
                if resp.status_code == 200:
                    raw = resp.json()
                    vulns_list = raw.get("vulnerabilities", [])
                    if vulns_list:
                        data = vulns_list[0].get("cve", {})
                        db.set_cache(f"cve:{cve_id}", json.dumps(data), ttl_seconds=3600)
                    else:
                        console.print(f"[yellow]CVE {cve_id} não encontrado na NVD.[/yellow]")
                        return
                else:
                    console.print(f"[yellow]NVD retornou status {resp.status_code}.[/yellow]")
                    return
            except Exception as e:
                console.print(f"[red]❌ Erro ao consultar NVD: {e}[/red]")
                return

    desc_items = data.get("descriptions", [])
    desc_en    = next((d["value"] for d in desc_items if d["lang"] == "en"), "N/A")

    metrics   = data.get("metrics", {})
    cvss_v3   = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    cvss_score = "N/A"
    cvss_sev   = "N/A"
    if cvss_v3:
        cvss_data  = cvss_v3[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", "N/A")
        cvss_sev   = cvss_data.get("baseSeverity", "N/A")

    published = data.get("published", "N/A")[:10]
    modified  = data.get("lastModified", "N/A")[:10]

    sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
    sev_color  = sev_colors.get(cvss_sev.upper(), "white")

    console.print(Panel(
        f"[bold]{cve_id}[/bold]\n\n"
        f"[yellow]CVSS Score:[/yellow] [{sev_color}]{cvss_score} ({cvss_sev})[/{sev_color}]\n"
        f"[yellow]Publicado:[/yellow]  {published}\n"
        f"[yellow]Atualizado:[/yellow] {modified}\n\n"
        f"[bold]Descrição:[/bold]\n{desc_en}\n\n"
        f"[dim]🔗 https://nvd.nist.gov/vuln/detail/{cve_id}[/dim]",
        title=f"[cyan]{cve_id}[/cyan]", border_style="cyan"
    ))

    refs = data.get("references", [])[:5]
    if refs:
        console.print("[bold]Referências:[/bold]")
        for ref in refs:
            console.print(f"  [blue]→[/blue] {ref.get('url', '')}")

    if ai.is_ready():
        if Confirm.ask("\n[cyan]Gerar análise de impacto e mitigação com IA?[/cyan]", default=False):
            prompt = (
                f"Analise o {cve_id} (CVSS: {cvss_score} - {cvss_sev}):\n\n"
                f"Descrição: {desc_en}\n\n"
                "Forneça:\n"
                "1. Explicação técnica da vulnerabilidade\n"
                "2. Quem é afetado e como identificar exposição\n"
                "3. Passos de mitigação e patch\n"
                "4. Indicadores de comprometimento (se aplicável)"
            )
            console.print("\n[bold cyan]MAI[/bold cyan]")
            for chunk in ai.stream_chat([{"role": "user", "content": prompt}]):
                console.print(chunk, end="", highlight=False)
            console.print()

# ─────────────────────────────────────────────────────────────────────────
# NEWS
# ─────────────────────────────────────────────────────────────────────────

@app.command(name="news", help="📰 Notícias de segurança")
def news_cmd(
    filter_risk: Optional[str] = typer.Option(None, "--filter", "-f", help="critical/high/medium/low"),
    limit: int = typer.Option(15, "--limit", "-l"),
    ai_summary: bool = typer.Option(False, "--ai"),
):
    _print_banner()

    with console.status("[blue]Buscando notícias...[/blue]"):
        news_agg.fetch()

    latest = db.get_latest_news(risk_level=filter_risk, limit=limit)

    if not latest:
        console.print("[yellow]Nenhuma notícia encontrada.[/yellow]")
        return

    table = Table(title="📰 Security Intelligence Feed", box=box.ROUNDED, show_header=True)
    table.add_column("Risco",  width=10)
    table.add_column("Título", style="cyan", max_width=50)
    table.add_column("Fonte",  style="yellow", width=18)
    table.add_column("Data",   style="magenta", width=12)

    for n in latest:
        color = _vuln_color(n["risk_level"])
        table.add_row(
            f"[{color}]{n['risk_level'].upper()}[/{color}]",
            n["title"][:50],
            n["source"][:18],
            n["published"][:10]
        )

    console.print(table)
    console.print(f"[dim]{len(latest)} notícias[/dim]")

    if ai_summary and ai.is_ready():
        headlines = "\n".join([f"- [{n['risk_level'].upper()}] {n['title']}" for n in latest[:10]])
        prompt = (
            f"Com base nestas notícias de segurança recentes:\n\n{headlines}\n\n"
            "Crie um briefing executivo de segurança com:\n"
            "1. Tendências e ameaças predominantes\n"
            "2. Setores/tecnologias mais impactados\n"
            "3. Ações imediatas recomendadas\n"
            "4. O que monitorar nas próximas semanas"
        )
        console.print("\n[bold cyan]MAI — Briefing de Segurança[/bold cyan]")
        for chunk in ai.stream_chat([{"role": "user", "content": prompt}]):
            console.print(chunk, end="", highlight=False)
        console.print()

# ─────────────────────────────────────────────────────────────────────────
# PROTECT
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="🛡️ Guia de hardening e proteção")
def protect(
    target: str = typer.Option("windows", "--target", "-t",
                                help="windows, linux, web-app, database, docker, ssh, cloud"),
    lgpd: bool = typer.Option(False, "--lgpd"),
    ai_guide: bool = typer.Option(False, "--ai"),
):
    _print_banner()

    RECOMMENDATIONS = {
        "windows": {
            "icon": "🪟", "title": "Windows System Hardening",
            "items": [
                ("Windows Update automático",    "Mantenha patches automáticos: Settings > Update & Security",          "critical"),
                ("Windows Defender / AV",        "Mantenha o Defender ativo e atualizado — ou use EDR corporativo",     "critical"),
                ("BitLocker",                    "Criptografe o disco: BitLocker em todas as partições",                "critical"),
                ("Firewall do Windows",          "Mantenha o Firewall ativo — perfis: Domain, Private, Public",         "critical"),
                ("UAC no nível máximo",          "User Account Control: sempre notificar em mudanças",                  "high"),
                ("Desativar RDP se não usar",    "Painel de Controle > Sistema > Configurações Remotas > desativar",    "high"),
                ("Contas sem privilégio adm",    "Use conta padrão no dia a dia — admin só quando necessário",          "high"),
                ("AppLocker / WDAC",             "Whitelisting de aplicações via AppLocker ou Windows Defender AC",     "high"),
                ("Auditoria de eventos",         "Event Viewer: habilite logon, acesso a objetos, uso de privilégios", "medium"),
                ("Powershell Constrained Lang",  "Restrinja Powershell com Constrained Language Mode + logging",       "medium"),
                ("Credencial Guard",             "Isole credenciais LSASS com Credential Guard (Windows 10/11 Pro+)",  "medium"),
                ("Backups offline (VSS/Robocopy)","Backup regular off-site — protege contra ransomware",               "high"),
            ]
        },
        "linux": {
            "icon": "🐧", "title": "Linux System Hardening",
            "items": [
                ("Atualizações automáticas",     "unattended-upgrades para patches de segurança automáticos",           "critical"),
                ("Firewall UFW/iptables",        "ufw enable && ufw default deny incoming && ufw allow ssh",            "critical"),
                ("SSH hardening",                "PermitRootLogin no | PasswordAuth no | Port != 22 | Ed25519",        "critical"),
                ("Fail2ban",                     "Bloqueio automático de brute-force: SSH, Apache, Nginx",             "high"),
                ("AppArmor/SELinux",             "Ative e configure perfis de controle de acesso obrigatório",         "high"),
                ("Desativar serviços desnecessários","systemctl disable bluetooth avahi-daemon cups",                  "high"),
                ("Auditd",                       "Auditoria de chamadas de sistema e acesso a arquivos",               "medium"),
                ("Lynis",                        "lynis audit system — score de hardening detalhado",                  "medium"),
                ("sysctl hardening",             "net.ipv4.tcp_syncookies=1, kernel.randomize_va_space=2",            "high"),
                ("ClamAV + rkhunter",            "Antivírus e detecção de rootkits",                                   "medium"),
                ("Backups criptografados",       "restic ou duplicati com GPG — 3-2-1 backup strategy",               "high"),
            ]
        },
        "web-app": {
            "icon": "🌐", "title": "Web Application Security",
            "items": [
                ("HTTPS obrigatório",       "TLS 1.2+ com Let's Encrypt + redirect 301 HTTP→HTTPS",                    "critical"),
                ("Security Headers",        "HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.",               "high"),
                ("WAF",                     "CloudFlare, ModSecurity, AWS WAF ou Nginx WAF",                          "high"),
                ("Rate limiting",           "Limite por IP: nginx limit_req, express-rate-limit",                     "high"),
                ("Prepared statements",     "ORM ou prepared statements — nunca concatenar SQL",                      "critical"),
                ("Validação de entrada",    "Valide e sanitize toda entrada: servidor E cliente",                     "critical"),
                ("Dependency scanning",     "npm audit, pip-audit, OWASP Dependency-Check em CI/CD",                 "high"),
                ("CORS restritivo",         "Nunca Access-Control-Allow-Origin: * em dados sensíveis",                "medium"),
                ("Logs centralizados",      "ELK Stack, Graylog ou AWS CloudWatch",                                   "medium"),
                ("OWASP Top 10 checklist",  "Revise os 10 riscos mais críticos a cada ciclo",                        "high"),
            ]
        },
        "database": {
            "icon": "🗄️", "title": "Database Security",
            "items": [
                ("Isolamento de rede",       "Banco NUNCA exposto à internet — apenas rede interna",                  "critical"),
                ("TLS nas conexões",         "Criptografe toda comunicação cliente-servidor",                         "critical"),
                ("Menor privilégio",         "Cada app usa usuário DB com permissões mínimas",                        "critical"),
                ("Criptografia em repouso",  "Dados PII criptografados: bcrypt senhas, AES-256 dados",               "critical"),
                ("Backups criptografados",   "Backup diário + teste de restauração + retenção 30 dias",              "high"),
                ("Auditoria de queries",     "Slow query log + log de acesso + alertas de anomalia",                 "medium"),
                ("Usuário root desabilitado","Nunca conecte como root — crie usuários específicos",                  "critical"),
                ("Atualizações",             "Mantenha versão do banco sempre na última LTS",                        "high"),
            ]
        },
        "docker": {
            "icon": "🐳", "title": "Container Security",
            "items": [
                ("Usuário não-root",         "USER nobody no Dockerfile — nunca rode como root",                      "critical"),
                ("Imagens oficiais",         "Use imagens oficiais com digest hash — não :latest",                   "high"),
                ("Read-only filesystem",     "--read-only + tmpfs para /tmp e volumes temporários",                  "medium"),
                ("Scan de imagens",          "trivy image, docker scout, Snyk Container",                            "high"),
                ("Secrets management",       "Docker Secrets ou Vault — NUNCA variáveis de ambiente",               "critical"),
                ("Network isolation",        "Redes bridge dedicadas por serviço — nunca --net=host",               "high"),
                ("Limitar recursos",         "--memory=512m --cpus=0.5 — evitar DoS por contêiner",                 "medium"),
                ("Rootless Docker",          "docker rootless mode ou Podman como alternativa",                      "high"),
            ]
        },
        "ssh": {
            "icon": "🔑", "title": "SSH Hardening",
            "items": [
                ("Trocar porta padrão",      "Port 22 → porta acima de 10000 no sshd_config",                        "medium"),
                ("Chaves Ed25519",           "ssh-keygen -t ed25519 — desative senha completamente",                "critical"),
                ("PermitRootLogin no",       "Nunca login direto como root via SSH",                                 "critical"),
                ("AllowUsers/AllowGroups",   "Whitelist de usuários/grupos no sshd_config",                         "high"),
                ("MaxAuthTries 3",           "Limite tentativas: MaxAuthTries 3 | LoginGraceTime 30",               "high"),
                ("2FA com Google Auth",      "libpam-google-authenticator ou TOTP no sshd",                         "high"),
                ("Fail2ban SSH",             "Bloqueio após 3 falhas, ban de 1 hora",                               "high"),
                ("Jump hosts / bastion",     "Use bastion host para acesso à infraestrutura interna",               "high"),
            ]
        },
        "cloud": {
            "icon": "☁️", "title": "Cloud Security (AWS/GCP/Azure)",
            "items": [
                ("MFA obrigatório",          "MFA em todas as contas — especialmente root/admin",                    "critical"),
                ("IAM com menor privilégio", "Nunca use AdministratorAccess — crie roles específicas",             "critical"),
                ("CloudTrail/Audit Logs",    "Ative logging de todas as ações em todos os serviços",               "critical"),
                ("Security Groups restritivos","Regras 0.0.0.0/0 apenas quando absolutamente necessário",          "high"),
                ("S3 Block Public Access",   "Bloqueie acesso público a todos os buckets por padrão",              "critical"),
                ("VPC e segmentação",        "Isole ambientes (prod/staging) em VPCs separadas",                   "high"),
                ("Criptografia KMS",         "Criptografe todos os dados em repouso com KMS gerenciado",           "high"),
                ("GuardDuty/Defender",       "Habilite detecção de ameaças nativa do cloud provider",             "high"),
                ("Credential rotation",      "Rotacione access keys a cada 90 dias — use IAM Roles",              "high"),
            ]
        },
    }

    if target not in RECOMMENDATIONS:
        options = ", ".join(RECOMMENDATIONS.keys())
        console.print(f"[red]❌ Alvo inválido. Opções: {options}[/red]")
        return

    rec = RECOMMENDATIONS[target]
    table = Table(
        title=f"{rec['icon']} {rec['title']}",
        show_header=True, show_lines=True, box=box.ROUNDED
    )
    table.add_column("Controle",   style="bold", width=30)
    table.add_column("Descrição",  width=52)
    table.add_column("Prioridade", width=10)

    for name, desc, priority in rec["items"]:
        color = _vuln_color(priority)
        table.add_row(name, desc, f"[{color}]{priority.upper()}[/{color}]")

    console.print(table)

    if lgpd:
        lgpd_items = [
            "Consentimento explícito e granular para cada finalidade de tratamento",
            "Política de privacidade clara, acessível e em linguagem simples",
            "Dados PII criptografados em repouso (AES-256) e em trânsito (TLS 1.3)",
            "Endpoint para exclusão de dados (Right to be Forgotten — Art. 18 LGPD)",
            "Notificação de incidente à ANPD em até 72h (Art. 48 LGPD)",
            "RIPD — Relatório de Impacto à Proteção de Dados documentado",
            "Registro de atividades de tratamento (Art. 37 LGPD) atualizado",
            "DPA (Data Processing Agreement) com todos os fornecedores/operadores",
            "DPO (Encarregado de Proteção de Dados) nomeado e acessível",
            "Auditoria anual de conformidade com evidências documentadas",
            "Treinamento de equipe em LGPD anualmente",
            "Inventário de dados pessoais (data mapping) atualizado",
        ]
        table2 = Table(title="📋 Checklist LGPD", show_header=False, box=box.SIMPLE)
        table2.add_column("Item", style="green")
        for item in lgpd_items:
            table2.add_row(f"  ☐  {item}")
        console.print(table2)

    if ai_guide and ai.is_ready():
        items_text = "\n".join([f"- {i[0]}: {i[1]}" for i in rec["items"][:8]])
        prompt = (
            f"Crie um guia técnico de hardening para '{target}'.\n"
            f"Controles:\n{items_text}\n\n"
            "Para os 4 itens mais críticos, forneça:\n"
            "- Comando ou configuração exata\n"
            "- Como verificar se está funcionando\n"
            "- Impacto de não implementar"
        )
        console.print("\n[bold cyan]MAI — Guia de Implementação[/bold cyan]")
        for chunk in ai.stream_chat([{"role": "user", "content": prompt}]):
            console.print(chunk, end="", highlight=False)
        console.print()

# ─────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="⚙️  Configurações da MAI")
def config(
    init: bool = typer.Option(False, "--init"),
    show: bool = typer.Option(False, "--show"),
    set_key: Optional[str] = typer.Option(None, "--set", help="KEY=valor"),
):
    _print_banner()

    if init:
        console.print(Panel(
            "[bold]Configuração inicial da MAI[/bold]\n\n"
            "Você precisa de uma GROQ API Key para usar o chat com IA.\n"
            "Crie sua chave [bold green]GRATUITA[/bold green] em:\n"
            "[link=https://console.groq.com]https://console.groq.com[/link]\n\n"
            f"[dim]Será salvo em: {ENV_FILE}[/dim]",
            border_style="cyan"
        ))

        groq_key = Prompt.ask("🔑 GROQ_API_KEY (Enter para pular)", default="", password=True)

        if groq_key and not re.match(r"^gsk_[A-Za-z0-9]{40,}$", groq_key):
            console.print("[yellow]⚠️  A chave parece inválida (deve começar com 'gsk_').[/yellow]")

        ENV_FILE.write_text(f"GROQ_API_KEY={groq_key}\n", encoding="utf-8")
        _secure_file(ENV_FILE)

        if groq_key:
            console.print(f"[green]✅ Configurado! Arquivo protegido em: {ENV_FILE}[/green]")
            console.print("[green]Execute: python mai.py chat[/green]")
        else:
            console.print("[yellow]⚠️  Sem API key o chat com IA não funcionará.[/yellow]")

    elif show:
        if ENV_FILE.exists():
            content = ENV_FILE.read_text(encoding="utf-8")
            masked  = re.sub(r"(=)(\w{4})(\w+)", r"\1\2****", content)
            console.print(Panel(
                f"{masked}\n[dim]Localização: {ENV_FILE}[/dim]",
                title="[cyan]Configuração[/cyan]"
            ))
        else:
            console.print("[yellow]Sem configuração. Execute: python mai.py config --init[/yellow]")

    elif set_key:
        if "=" not in set_key:
            value   = Prompt.ask(f"Valor para {set_key}", password=True)
            set_key = f"{set_key}={value}"

        key, value = set_key.split("=", 1)
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}"
                found = True
                break
        if not found:
            lines.append(f"{key}={value}")

        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _secure_file(ENV_FILE)
        console.print(f"[green]✅ {key} configurado![/green]")

    else:
        console.print("[yellow]Use --init, --show ou --set KEY=valor[/yellow]")

# ─────────────────────────────────────────────────────────────────────────
# HISTORY
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="📜 Histórico de scans")
def history(
    limit: int = typer.Option(15, "--limit", "-l"),
    show_json: bool = typer.Option(False, "--json", help="Exportar como JSON"),
):
    _print_banner()

    scans = db.get_scan_history(limit=limit)

    if not scans:
        console.print("[yellow]Nenhum scan encontrado.[/yellow]")
        return

    if show_json:
        console.print(json.dumps(scans, indent=2, default=str))
        return

    table = Table(title="📜 Histórico de Scans", show_header=True, box=box.ROUNDED)
    table.add_column("ID",    style="dim cyan",  width=10)
    table.add_column("Tipo",  style="magenta",   width=8)
    table.add_column("Alvo",  style="yellow",    width=45)
    table.add_column("Score",                    width=10)
    table.add_column("Data",  style="blue",      width=12)

    for s in scans:
        score = s.get("score") or 0
        color = _score_color(score)
        table.add_row(
            s["id"][:8],
            s["scan_type"],
            s["target"][:45],
            f"[{color}]{score:.0f}[/{color}]",
            s["timestamp"][:10]
        )

    console.print(table)

# ─────────────────────────────────────────────────────────────────────────
# INFO
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="ℹ️  Informações sobre a MAI")
def info():
    _print_banner()

    has_key = bool(
        os.getenv("GROQ_API_KEY") or
        (ENV_FILE.exists() and "GROQ_API_KEY" in ENV_FILE.read_text(encoding="utf-8"))
    )
    key_status = "[green]✅ Configurada[/green]" if has_key else "[red]❌ Não configurada[/red]"

    platform_name = (
        f"Windows {sys.getwindowsversion().major}.{sys.getwindowsversion().minor}"
        if IS_WINDOWS else sys.platform
    )

    table = Table(title="📋 MAI v3.0", show_header=False, box=None)
    table.add_column("Campo", style="cyan", width=20)
    table.add_column("Valor")
    rows = [
        ("Versão",        "3.0.0"),
        ("Python",        sys.version.split()[0]),
        ("Plataforma",    platform_name),
        ("GROQ API Key",  key_status),
        ("Modelo IA",     "llama-3.3-70b-versatile (Groq)"),
        ("Banco de dados",str(DB_PATH)),
        ("Config",        str(ENV_FILE)),
        ("Log",           str(LOG_FILE)),
    ]
    for r in rows:
        table.add_row(*r)
    console.print(table)

    console.print(Panel(
        "[bold]Comandos disponíveis:[/bold]\n\n"
        "  [cyan]chat[/cyan]                          Chat livre com IA\n"
        "  [cyan]scan https://site.com[/cyan]         Scan de segurança web\n"
        "  [cyan]scan arquivo.py -t code[/cyan]       Análise estática de código\n"
        "  [cyan]dns exemplo.com[/cyan]               Análise de DNS, SPF, DMARC, WHOIS\n"
        "  [cyan]headers https://site.com[/cyan]      Análise de headers HTTP\n"
        "  [cyan]cve CVE-2024-1234[/cyan]             Consultar CVE na NVD\n"
        "  [cyan]news --ai[/cyan]                     Notícias + briefing executivo IA\n"
        "  [cyan]protect -t windows --ai[/cyan]       Hardening Windows + guia de implementação\n"
        "  [cyan]protect -t linux --lgpd[/cyan]       Hardening Linux + checklist LGPD\n"
        "  [cyan]config --init[/cyan]                 Configurar API key\n"
        "  [cyan]history[/cyan]                       Histórico de scans\n"
        "  [cyan]install[/cyan]                       Instalar dependências",
        title="[cyan]Uso[/cyan]", border_style="cyan"
    ))

# ─────────────────────────────────────────────────────────────────────────
# INSTALL
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="📦 Instala dependências")
def install():
    _print_banner()
    install_all(verbose=True)
    console.print("\n[dim]Próximo passo: python mai.py config --init[/dim]")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    # Habilitar suporte a Unicode/ANSI no terminal Windows
    if IS_WINDOWS:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Habilita ENABLE_VIRTUAL_TERMINAL_PROCESSING (modo ANSI)
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
        # Configura UTF-8 no stdout para evitar erros com emojis
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8")
            except Exception:
                pass

    if ENV_FILE.exists():
        load_dotenv(ENV_FILE, override=True)
    app()

if __name__ == "__main__":
    main()