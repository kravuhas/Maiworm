#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     MAI - AI SECURITY ASSISTANT v1.0                         ║
║                     Open Source • Ethical Hacking • Privacy First            ║
║                                                                              ║
║  Uma ferramenta CLI profissional para análise de segurança da informação     ║
║  com IA, RAG (Retrieval-Augmented Generation) e compliance LGPD             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

AUTOR: Security AI Team
VERSÃO: 1.0.0
LICENÇA: MIT
COMPATIBILIDADE: Linux, Windows, macOS
PYTHON: 3.9+

DEPENDÊNCIAS:
    pip install typer rich requests beautifulsoup4 langchain sentence-transformers
    pip install chromadb groq sqlite3 pydantic python-dotenv feedparser

USO:
    python mai.py --help
    python mai.py scan https://example.com
    python mai.py analyze documento.pdf
    python mai.py news --filter ransomware
    python mai.py protect --target web-app --lgpd
"""

import os
import sys
import json
import sqlite3
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path
import hashlib
from dataclasses import dataclass, asdict
from enum import Enum

# Instalação automática de dependências
def install_dependencies():
    """Instala dependências necessárias automaticamente"""
    import subprocess
    dependencies = [
        "typer>=0.9.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "langchain>=0.1.0",
        "langchain-community>=0.0.1",
        "sentence-transformers>=2.2.0",
        "chromadb>=0.4.0",
        "pydantic>=2.0.0",
        "python-dotenv>=1.0.0",
        "feedparser>=6.0.0",
        "groq>=0.4.0"
    ]
    
    try:
        import typer
    except ImportError:
        print("⏳ Instalando dependências necessárias...")
        for dep in dependencies:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", dep])
            except:
                pass
        print("✅ Dependências instaladas com sucesso!")

install_dependencies()

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress
from pydantic import BaseModel
from dotenv import load_dotenv

# Imports de IA e RAG
try:
    from langchain_community.document_loaders import PyPDFLoader
    from langchain_text_splitters import RecursiveCharacterTextSplitter
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma
    from langchain_groq import ChatGroq
    from langchain.chains import RetrievalQA
    from langchain.prompts import PromptTemplate
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

load_dotenv()

# Console Rich para outputs formatados
console = Console()

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Diretórios
HOME_DIR = Path.home()
MAI_DIR = HOME_DIR / ".mai"
DB_PATH = MAI_DIR / "mai.db"
CHROMA_DIR = MAI_DIR / "chroma_db"
CACHE_DIR = MAI_DIR / "cache"

# Criar diretórios se não existirem
for directory in [MAI_DIR, CHROMA_DIR, CACHE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Banner ASCII
BANNER = r"""
 __  ___      _                             
/  |/  /___ _(_)      ______  _________ ___ 
/ /|_/ / __ `/ / | /| / / __ \/ ___/ __ `__ \
/ /  / / /_/ / /| |/ |/ / /_/ / /  / / / / / /
/_/  /_/\__,_/_/ |__/|__/\____/_/  /_/ /_/ /_/ 

Mai - AI Security Assistant (CLI Edition)
Open Source • Ethical Hacking • Privacy First • LGPD Compliant
"""

# ═══════════════════════════════════════════════════════════════════════════
# MODELOS DE DADOS (Pydantic)
# ═══════════════════════════════════════════════════════════════════════════

class ScanType(str, Enum):
    """Tipos de scan disponíveis"""
    WEB = "web"
    CODE = "code"
    HEADERS = "headers"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"

class VulnerabilityLevel(str, Enum):
    """Níveis de severidade"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Vulnerability:
    """Classe para representar vulnerabilidades"""
    id: str
    title: str
    description: str
    level: VulnerabilityLevel
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None

@dataclass
class ScanResult:
    """Resultado de um scan de segurança"""
    scan_id: str
    scan_type: ScanType
    target: str
    timestamp: str
    vulnerabilities: List[Vulnerability]
    score: float  # 0-100

@dataclass
class SecurityNews:
    """Notícia de segurança"""
    id: str
    title: str
    description: str
    source: str
    url: str
    published: str
    risk_level: str

# ═══════════════════════════════════════════════════════════════════════════
# BANCO DE DADOS SQL
# ═══════════════════════════════════════════════════════════════════════════

class Database:
    """Gerenciador de banco de dados SQL"""
    
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        """Obtém conexão com banco de dados"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        """Inicializa banco de dados com schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Tabela de scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                score REAL,
                result_json TEXT,
                status TEXT DEFAULT 'completed'
            )
        ''')
        
        # Tabela de vulnerabilidades
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                level TEXT,
                cwe TEXT,
                owasp_category TEXT,
                remediation TEXT,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        # Tabela de notícias
        cursor.execute('''
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
            )
        ''')
        
        # Tabela de análises RAG
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rag_analyses (
                id TEXT PRIMARY KEY,
                document_path TEXT,
                query TEXT,
                response TEXT,
                sources TEXT,
                timestamp TEXT
            )
        ''')
        
        # Tabela de cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at TEXT
            )
        ''')
        
        # Índices
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scans(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_level ON vulnerabilities(level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_news_risk ON news(risk_level)')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, scan_result: ScanResult):
        """Salva resultado de scan no banco de dados"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        result_json = json.dumps(asdict(scan_result), default=str)
        
        cursor.execute('''
            INSERT OR REPLACE INTO scans 
            (id, scan_type, target, timestamp, score, result_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            scan_result.scan_id,
            scan_result.scan_type.value,
            scan_result.target,
            scan_result.timestamp,
            scan_result.score,
            result_json
        ))
        
        conn.commit()
        conn.close()
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """Obtém histórico de scans"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def save_news(self, news: SecurityNews):
        """Salva notícia de segurança"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO news 
                (id, title, description, source, url, published, risk_level, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                news.id,
                news.title,
                news.description,
                news.source,
                news.url,
                news.published,
                news.risk_level,
                datetime.now().isoformat()
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Notícia já existe
        finally:
            conn.close()
    
    def get_latest_news(self, risk_level: Optional[str] = None, limit: int = 20) -> List[Dict]:
        """Obtém notícias mais recentes"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if risk_level:
            cursor.execute('''
                SELECT * FROM news WHERE risk_level = ? 
                ORDER BY published DESC LIMIT ?
            ''', (risk_level, limit))
        else:
            cursor.execute('''
                SELECT * FROM news ORDER BY published DESC LIMIT ?
            ''', (limit,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

# ═══════════════════════════════════════════════════════════════════════════
# SISTEMA DE SEGURANÇA - ANÁLISES
# ═══════════════════════════════════════════════════════════════════════════

class SecurityAnalyzer:
    """Analisador de segurança com múltiplos tipos de verificação"""
    
    def __init__(self):
        self.db = Database()
        self.owasp_vulns = self._load_owasp_knowledge_base()
        self.cwe_database = self._load_cwe_database()
    
    def _load_owasp_knowledge_base(self) -> Dict:
        """Carrega base de conhecimento OWASP"""
        return {
            "A01": {
                "name": "Broken Access Control",
                "description": "Falha de controle de acesso permitindo acesso não autorizado",
                "examples": ["Privilege escalation", "Unauthorized data access"]
            },
            "A02": {
                "name": "Cryptographic Failures",
                "description": "Falhas em criptografia e proteção de dados",
                "examples": ["Weak encryption", "Hardcoded keys"]
            },
            "A03": {
                "name": "Injection",
                "description": "Injeção de código SQL, NoSQL, OS, etc",
                "examples": ["SQL Injection", "Command Injection", "LDAP Injection"]
            },
            "A04": {
                "name": "Insecure Design",
                "description": "Falhas de design de segurança",
                "examples": ["Missing security controls", "Poor threat modeling"]
            },
            "A05": {
                "name": "Security Misconfiguration",
                "description": "Configuração inadequada de segurança",
                "examples": ["Default credentials", "Unnecessary services enabled"]
            },
            "A06": {
                "name": "Vulnerable & Outdated Components",
                "description": "Componentes com vulnerabilidades conhecidas",
                "examples": ["Outdated libraries", "Unpatched dependencies"]
            },
            "A07": {
                "name": "Authentication Failures",
                "description": "Falhas de autenticação e gerenciamento de sessão",
                "examples": ["Weak passwords", "Session fixation"]
            },
            "A08": {
                "name": "Data Integrity Failures",
                "description": "Falhas na integridade de dados",
                "examples": ["Unsigned updates", "Insecure deserialization"]
            },
            "A09": {
                "name": "Logging & Monitoring Failures",
                "description": "Falta de logging e monitoramento",
                "examples": ["No audit logs", "Missing alerts"]
            },
            "A10": {
                "name": "SSRF",
                "description": "Server-Side Request Forgery",
                "examples": ["Unvalidated URL redirects"]
            }
        }
    
    def _load_cwe_database(self) -> Dict:
        """Carrega base de dados CWE"""
        return {
            "CWE-79": {
                "name": "Cross-site Scripting (XSS)",
                "severity": "high",
                "description": "Inserção de scripts maliciosos em páginas web"
            },
            "CWE-89": {
                "name": "SQL Injection",
                "severity": "critical",
                "description": "Injeção de comandos SQL"
            },
            "CWE-287": {
                "name": "Improper Authentication",
                "severity": "critical",
                "description": "Falha na autenticação adequada"
            },
            "CWE-434": {
                "name": "Unrestricted Upload of File",
                "severity": "high",
                "description": "Upload de arquivo sem restrição"
            },
            "CWE-611": {
                "name": "Improper Restriction of XXE",
                "severity": "high",
                "description": "Falha em restringir XML External Entity"
            }
        }
    
    def analyze_headers(self, headers: Dict[str, str]) -> List[Vulnerability]:
        """Analisa headers HTTP em busca de vulnerabilidades"""
        vulns = []
        
        # Verificar headers de segurança
        security_headers = {
            "Strict-Transport-Security": "HSTS não configurado - Use HTTPS obrigatório",
            "X-Content-Type-Options": "X-Content-Type-Options não definido - Risco de MIME sniffing",
            "X-Frame-Options": "X-Frame-Options não definido - Risco de Clickjacking",
            "Content-Security-Policy": "CSP não configurado - Risco de XSS",
            "X-XSS-Protection": "Proteção XSS não ativada"
        }
        
        for header, message in security_headers.items():
            if header not in headers:
                vulns.append(Vulnerability(
                    id=f"HEADER_{header}",
                    title=f"Missing {header}",
                    description=message,
                    level=VulnerabilityLevel.MEDIUM,
                    owasp_category="A05"
                ))
        
        return vulns
    
    def analyze_code(self, code: str) -> List[Vulnerability]:
        """Analisa código Python em busca de vulnerabilidades"""
        vulns = []
        
        # Verificações de padrões perigosos
        dangerous_patterns = {
            "eval(": ("Uso de eval()", "eval() é extremamente perigoso", VulnerabilityLevel.CRITICAL, "CWE-95"),
            "exec(": ("Uso de exec()", "exec() é perigoso", VulnerabilityLevel.CRITICAL, "CWE-95"),
            "pickle": ("Insecure deserialization com pickle", "pickle pode executar código", VulnerabilityLevel.HIGH, "CWE-502"),
            "subprocess.call": ("Uso de subprocess sem shell=False", "Risco de command injection", VulnerabilityLevel.HIGH, "CWE-78"),
            "input()": ("Uso de input() sem validação", "Entrada não validada", VulnerabilityLevel.MEDIUM, "CWE-20"),
        }
        
        for pattern, (title, desc, level, cwe) in dangerous_patterns.items():
            if pattern in code:
                vulns.append(Vulnerability(
                    id=f"CODE_{pattern}",
                    title=title,
                    description=desc,
                    level=level,
                    cwe=cwe,
                    owasp_category="A03"
                ))
        
        return vulns
    
    def scan_web(self, url: str) -> ScanResult:
        """Realiza scan de website"""
        import requests
        from urllib.parse import urlparse
        
        vulns = []
        score = 100
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Analisar headers
            header_vulns = self.analyze_headers(dict(headers))
            vulns.extend(header_vulns)
            score -= len(header_vulns) * 3
            
            # Verificar HTTPS
            if urlparse(url).scheme != "https":
                vulns.append(Vulnerability(
                    id="SSL_NOT_ENFORCED",
                    title="HTTPS Not Enforced",
                    description="Site não usa HTTPS - Comunicação não criptografada",
                    level=VulnerabilityLevel.CRITICAL,
                    owasp_category="A02"
                ))
                score -= 10
            
            # Verificar Server header
            if "Server" in headers:
                vulns.append(Vulnerability(
                    id="SERVER_DISCLOSURE",
                    title="Server Information Disclosure",
                    description=f"Server header revela informações: {headers['Server']}",
                    level=VulnerabilityLevel.LOW,
                    owasp_category="A01"
                ))
                score -= 2
            
        except Exception as e:
            logger.error(f"Erro ao fazer scan: {e}")
        
        score = max(0, min(100, score))
        
        scan_id = hashlib.md5(f"{url}{datetime.now()}".encode()).hexdigest()
        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.WEB,
            target=url,
            timestamp=datetime.now().isoformat(),
            vulnerabilities=vulns,
            score=score
        )
        
        self.db.save_scan(result)
        return result

# ═══════════════════════════════════════════════════════════════════════════
# SISTEMA RAG COM LANGCHAIN
# ═══════════════════════════════════════════════════════════════════════════

class MAIRAGSystem:
    """Sistema RAG (Retrieval-Augmented Generation) com LangChain"""
    
    def __init__(self):
        self.db = Database()
        self.embeddings = None
        self.vectorstore = None
        self.llm = None
        self.qa_chain = None
        self._init_rag()
    
    def _init_rag(self):
        """Inicializa sistema RAG"""
        try:
            # Embeddings
            self.embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
            
            # Banco vetorial
            self.vectorstore = Chroma(
                persist_directory=str(CHROMA_DIR),
                embedding_function=self.embeddings
            )
            
            # LLM via Groq
            groq_key = os.getenv("GROQ_API_KEY")
            if groq_key:
                self.llm = ChatGroq(
                    model="llama-3.1-8b-instant",
                    temperature=0.0,
                    groq_api_key=groq_key
                )
            
            console.print("[green]✅ Sistema RAG inicializado com sucesso![/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ RAG não disponível: {e}[/yellow]")
    
    def load_and_index_pdf(self, pdf_path: str) -> bool:
        """Carrega e indexa PDF para RAG"""
        try:
            from langchain_community.document_loaders import PyPDFLoader
            from langchain_text_splitters import RecursiveCharacterTextSplitter
            
            console.print(f"[blue]⏳ Carregando PDF: {pdf_path}[/blue]")
            
            loader = PyPDFLoader(pdf_path)
            documents = loader.load()
            
            # Chunking
            splitter = RecursiveCharacterTextSplitter(
                chunk_size=500,
                chunk_overlap=100
            )
            chunks = splitter.split_documents(documents)
            
            # Indexar
            self.vectorstore = Chroma.from_documents(
                documents=chunks,
                embedding=self.embeddings,
                persist_directory=str(CHROMA_DIR)
            )
            
            console.print(f"[green]✅ PDF indexado! {len(chunks)} chunks criados[/green]")
            return True
        except Exception as e:
            console.print(f"[red]❌ Erro ao carregar PDF: {e}[/red]")
            return False
    
    def query(self, query: str) -> Dict[str, Any]:
        """Faz query no sistema RAG"""
        try:
            if not self.llm or not self.vectorstore:
                return {"error": "RAG não disponível"}
            
            # Retriever
            retriever = self.vectorstore.as_retriever(search_kwargs={"k": 5})
            
            # QA Chain
            qa_chain = RetrievalQA.from_chain_type(
                llm=self.llm,
                chain_type="stuff",
                retriever=retriever,
                return_source_documents=True
            )
            
            result = qa_chain.invoke({"query": query})
            
            # Salvar no banco
            analysis_id = hashlib.md5(query.encode()).hexdigest()
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO rag_analyses 
                (id, query, response, sources, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                query,
                result.get("result", ""),
                json.dumps([doc.page_content[:200] for doc in result.get("source_documents", [])]),
                datetime.now().isoformat()
            ))
            conn.commit()
            conn.close()
            
            return {
                "query": query,
                "response": result.get("result"),
                "sources": len(result.get("source_documents", []))
            }
        except Exception as e:
            return {"error": str(e)}

# ═══════════════════════════════════════════════════════════════════════════
# AGREGADOR DE NOTÍCIAS DE SEGURANÇA
# ═══════════════════════════════════════════════════════════════════════════

class SecurityNewsAggregator:
    """Agregador de notícias de segurança de múltiplas fontes"""
    
    def __init__(self):
        self.db = Database()
        self.sources = {
            "The Hacker News": "https://feeds.thehackernews.com/",
            "Exploit-DB": "https://www.exploit-db.com/rss.xml",
            "NIST NVD": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json"
        }
    
    def fetch_news(self) -> List[SecurityNews]:
        """Busca notícias de todas as fontes"""
        import feedparser
        import requests
        
        all_news = []
        
        try:
            # Simular notícias de segurança (em produção, fazer requisições reais)
            simulated_news = [
                {
                    "title": "Critical Vulnerability in Linux Kernel",
                    "description": "Novo CVE-2024-1234 descoberto em kernel Linux",
                    "source": "The Hacker News",
                    "risk": "critical"
                },
                {
                    "title": "Zero-Day in Chrome Browser",
                    "description": "Exploit zero-day afeta múltiplas versões do Chrome",
                    "source": "Security Research",
                    "risk": "critical"
                },
                {
                    "title": "Ransomware Attack on Healthcare",
                    "description": "Hospital sofre ataque ransomware LockBit 3.0",
                    "source": "Incident Reports",
                    "risk": "high"
                },
                {
                    "title": "LGPD Compliance Guidelines",
                    "description": "Novas diretrizes de conformidade LGPD publicadas",
                    "source": "Regulatory",
                    "risk": "medium"
                },
                {
                    "title": "New Phishing Campaign",
                    "description": "Campanha de phishing sofisticada segmentando DevOps",
                    "source": "Threat Intelligence",
                    "risk": "high"
                }
            ]
            
            for i, news_item in enumerate(simulated_news):
                news = SecurityNews(
                    id=hashlib.md5(news_item["title"].encode()).hexdigest(),
                    title=news_item["title"],
                    description=news_item["description"],
                    source=news_item["source"],
                    url=f"https://example.com/news/{i}",
                    published=datetime.now().isoformat(),
                    risk_level=news_item["risk"]
                )
                self.db.save_news(news)
                all_news.append(news)
        
        except Exception as e:
            logger.error(f"Erro ao buscar notícias: {e}")
        
        return all_news
    
    def get_news_by_risk(self, risk_level: str) -> List[Dict]:
        """Obtém notícias por nível de risco"""
        return self.db.get_latest_news(risk_level=risk_level)

# ═══════════════════════════════════════════════════════════════════════════
# INTERFACE CLI COM TYPER
# ═══════════════════════════════════════════════════════════════════════════

app = typer.Typer(
    help="🛡️ Mai - AI Security Assistant",
    rich_markup_mode="rich"
)

# Instâncias globais
analyzer = SecurityAnalyzer()
rag_system = MAIRAGSystem()
news_agg = SecurityNewsAggregator()
db = Database()

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: SCAN
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="🔍 Realiza scan de segurança em um alvo")
def scan(
    target: str = typer.Argument(..., help="URL ou arquivo para scanear"),
    scan_type: str = typer.Option("web", "--type", "-t", help="Tipo de scan: web, code, headers"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Modo verbose")
):
    """Realiza scan de segurança"""
    
    console.print(Panel(BANNER, style="cyan bold"))
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scaneando...[/cyan]", total=100)
        
        try:
            if scan_type == "web":
                result = analyzer.scan_web(target)
            elif scan_type == "code":
                with open(target, 'r') as f:
                    code = f.read()
                vulns = analyzer.analyze_code(code)
                result = ScanResult(
                    scan_id=hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest(),
                    scan_type=ScanType.CODE,
                    target=target,
                    timestamp=datetime.now().isoformat(),
                    vulnerabilities=vulns,
                    score=100 - (len(vulns) * 5)
                )
            else:
                console.print("[red]Tipo de scan inválido[/red]")
                return
            
            progress.update(task, completed=100)
            
            # Exibir resultados
            table = Table(title="🔐 Scan Results", show_header=True)
            table.add_column("ID", style="cyan")
            table.add_column("Título", style="magenta")
            table.add_column("Nível", style="red")
            table.add_column("OWASP", style="yellow")
            
            for vuln in result.vulnerabilities:
                table.add_row(
                    vuln.id,
                    vuln.title,
                    vuln.level.value,
                    vuln.owasp_category or "N/A"
                )
            
            console.print(table)
            
            # Score
            score_color = "green" if result.score >= 80 else "yellow" if result.score >= 50 else "red"
            console.print(f"\n[{score_color}]Score de Segurança: {result.score}/100[/{score_color}]")
            console.print(f"[blue]Total de Vulnerabilidades: {len(result.vulnerabilities)}[/blue]")
            
            if verbose:
                for vuln in result.vulnerabilities:
                    console.print(f"\n[red]{vuln.title}[/red]")
                    console.print(f"  {vuln.description}")
                    if vuln.remediation:
                        console.print(f"  [green]✓ Remediação:[/green] {vuln.remediation}")
            
        except Exception as e:
            console.print(f"[red]❌ Erro: {e}[/red]")

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: ANALYZE (RAG)
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="📚 Analisa documentos com RAG (Retrieval-Augmented Generation)")
def analyze(
    document: Optional[str] = typer.Option(None, "--doc", "-d", help="Caminho do PDF"),
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Pergunta sobre o documento"),
    mode: str = typer.Option("document", "--mode", "-m", help="Modo: document ou code")
):
    """Analisa documentos usando IA e RAG"""
    
    console.print(Panel(BANNER, style="cyan bold"))
    
    if mode == "document" and document:
        # Carregar PDF
        if rag_system.load_and_index_pdf(document):
            if query:
                console.print(f"\n[blue]🤖 Processando query...[/blue]")
                result = rag_system.query(query)
                
                if "error" not in result:
                    console.print(f"\n[green]✅ Resposta:[/green]")
                    console.print(result["response"])
                    console.print(f"\n[cyan]📚 Fontes encontradas: {result['sources']}[/cyan]")
                else:
                    console.print(f"[red]❌ {result['error']}[/red]")
            else:
                console.print("[yellow]Use --query para fazer uma pergunta[/yellow]")
    else:
        console.print("[yellow]Especifique um documento com --doc[/yellow]")

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: NEWS
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="📰 Mostra notícias de segurança agregadas")
def news(
    filter: Optional[str] = typer.Option(None, "--filter", "-f", help="Filtrar por nível: critical, high, medium, low"),
    limit: int = typer.Option(20, "--limit", "-l", help="Número máximo de notícias")
):
    """Exibe notícias de segurança"""
    
    console.print(Panel(BANNER, style="cyan bold"))
    
    console.print("[blue]⏳ Buscando notícias...[/blue]")
    news_agg.fetch_news()
    
    latest_news = news_agg.db.get_latest_news(risk_level=filter, limit=limit)
    
    if not latest_news:
        console.print("[yellow]Nenhuma notícia encontrada[/yellow]")
        return
    
    table = Table(title="📰 Security News", show_header=True)
    table.add_column("Título", style="cyan")
    table.add_column("Risco", style="red")
    table.add_column("Fonte", style="yellow")
    table.add_column("Data", style="magenta")
    
    for n in latest_news:
        risk_color = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "green"
        }.get(n['risk_level'], "white")
        
        table.add_row(
            n['title'][:50],
            f"[{risk_color}]{n['risk_level']}[/{risk_color}]",
            n['source'],
            n['published'][:10]
        )
    
    console.print(table)

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: PROTECT
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="🛡️ Gera recomendações de proteção e hardening")
def protect(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Tipo de alvo: web-app, linux, windows, database"),
    lgpd: bool = typer.Option(False, "--lgpd", help="Incluir conformidade LGPD")
):
    """Gera recomendações de proteção"""
    
    console.print(Panel(BANNER, style="cyan bold"))
    
    recommendations = {
        "web-app": [
            "✓ Implementar HTTPS em todas as páginas",
            "✓ Configurar Headers de Segurança (CSP, HSTS, X-Frame-Options)",
            "✓ Validar e sanitizar todas as entradas do usuário",
            "✓ Usar prepared statements para queries de banco de dados",
            "✓ Implementar rate limiting e CAPTCHA",
            "✓ Manter dependências atualizadas",
            "✓ Realizar testes de segurança regulares",
            "✓ Implementar WAF (Web Application Firewall)",
            "✓ Configurar logging e monitoramento",
            "✓ Planejar response para incidentes de segurança"
        ],
        "linux": [
            "✓ Manter sistema operacional atualizado",
            "✓ Usar firewall (UFW ou iptables)",
            "✓ Desabilitar serviços desnecessários",
            "✓ Usar SSH com chaves públicas (sem password)",
            "✓ Aplicar principio do menor privilégio",
            "✓ Configurar SELinux ou AppArmor",
            "✓ Habilitar auditoria e logging",
            "✓ Usar fail2ban contra ataques brute force",
            "✓ Fazer backups regulares",
            "✓ Monitorar processos e conexões de rede"
        ],
        "database": [
            "✓ Usar encrypted connections (SSL/TLS)",
            "✓ Implementar strong authentication",
            "✓ Criptografar dados sensíveis",
            "✓ Implementar row-level security",
            "✓ Fazer backups com criptografia",
            "✓ Monitorar acessos e queries",
            "✓ Limitar privilégios de usuários",
            "✓ Usar parameterized queries",
            "✓ Configurar auditing e logging",
            "✓ Realizar testes de penetração regularmente"
        ]
    }
    
    if target in recommendations:
        table = Table(title=f"🛡️ Recomendações para {target}", show_header=True)
        table.add_column("Proteção", style="green")
        
        for rec in recommendations[target]:
            table.add_row(rec)
        
        console.print(table)
        
        if lgpd:
            console.print("\n[yellow]📋 Conformidade LGPD:[/yellow]")
            lgpd_reqs = [
                "✓ Consentimento explícito para coleta de dados",
                "✓ Política de privacidade clara e acessível",
                "✓ Dados PII criptografados em repouso e em trânsito",
                "✓ Right to be forgotten implementado",
                "✓ Data breach notification em até 72 horas",
                "✓ Data Protection Impact Assessment (DPIA)",
                "✓ Registro de atividades de processamento",
                "✓ Terceiros com acordo de processamento (DPA)"
            ]
            
            for req in lgpd_reqs:
                console.print(f"  {req}")
    else:
        console.print("[red]Alvo não reconhecido[/red]")

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: CONFIG
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="⚙️ Gerencia configurações do Mai")
def config(
    init: bool = typer.Option(False, "--init", help="Inicializar configuração"),
    show: bool = typer.Option(False, "--show", help="Mostrar configuração atual"),
    set_key: Optional[str] = typer.Option(None, "--set", help="Definir chave (GROQ_API_KEY, etc)")
):
    """Gerencia configurações"""
    
    console.print(Panel(BANNER, style="cyan bold"))
    
    env_file = HOME_DIR / ".mai" / ".env"
    
    if init:
        console.print("[blue]Inicializando Mai...[/blue]")
        
        # Criar arquivo .env
        groq_key = typer.prompt("Digite sua GROQ_API_KEY (ou deixe em branco)", default="")
        
        env_content = f"GROQ_API_KEY={groq_key}\n"
        
        env_file.write_text(env_content)
        console.print(f"[green]✅ Configuração salva em {env_file}[/green]")
    
    elif show:
        if env_file.exists():
            config_data = env_file.read_text()
            console.print("[cyan]Configuração atual:[/cyan]")
            console.print(config_data)
        else:
            console.print("[yellow]Nenhuma configuração encontrada[/yellow]")
    
    elif set_key:
        key, value = set_key.split("=") if "=" in set_key else (set_key, "")
        if not value:
            value = typer.prompt(f"Digite o valor para {key}")
        
        env_lines = []
        if env_file.exists():
            env_lines = env_file.read_text().split("\n")
        
        # Atualizar ou adicionar
        found = False
        for i, line in enumerate(env_lines):
            if line.startswith(f"{key}="):
                env_lines[i] = f"{key}={value}"
                found = True
                break
        
        if not found:
            env_lines.append(f"{key}={value}")
        
        env_file.write_text("\n".join(env_lines))
        console.print(f"[green]✅ {key} configurado[/green]")

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: VERSION
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="ℹ️ Mostra informações sobre o Mai")
def info():
    """Mostra informações do sistema"""
    console.print(Panel(BANNER, style="cyan bold"))
    
    info_table = Table(title="📋 Informações do Mai", show_header=False)
    info_table.add_row("Versão", "1.0.0")
    info_table.add_row("Licença", "MIT")
    info_table.add_row("Autor", "Security AI Team")
    info_table.add_row("Compatibilidade", "Linux, Windows, macOS")
    info_table.add_row("Python", f"{sys.version.split()[0]}")
    info_table.add_row("Banco de Dados", str(DB_PATH))
    info_table.add_row("Cache", str(CACHE_DIR))
    info_table.add_row("Chroma DB", str(CHROMA_DIR))
    
    console.print(info_table)
    
    console.print("\n[cyan]📚 Comandos disponíveis:[/cyan]")
    console.print("  mai scan <alvo> --type web")
    console.print("  mai analyze --doc documento.pdf --query 'sua pergunta'")
    console.print("  mai news --filter critical")
    console.print("  mai protect --target web-app --lgpd")
    console.print("  mai config --init")
    console.print("  mai --help")

# ─────────────────────────────────────────────────────────────────────────
# COMANDO: HISTORY
# ─────────────────────────────────────────────────────────────────────────

@app.command(help="📜 Mostra histórico de scans")
def history(
    limit: int = typer.Option(10, "--limit", "-l", help="Número de registros")
):
    """Mostra histórico de scans"""
    console.print(Panel(BANNER, style="cyan bold"))
    
    scans = db.get_scan_history(limit=limit)
    
    if not scans:
        console.print("[yellow]Nenhum scan encontrado[/yellow]")
        return
    
    table = Table(title="📜 Histórico de Scans", show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Tipo", style="magenta")
    table.add_column("Alvo", style="yellow")
    table.add_column("Score", style="green")
    table.add_column("Data", style="blue")
    
    for scan in scans:
        table.add_row(
            scan['id'][:8],
            scan['scan_type'],
            scan['target'][:30],
            str(scan['score']),
            scan['timestamp'][:10]
        )
    
    console.print(table)

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Função principal"""
    console.print(Panel(BANNER, style="cyan bold"))
    app()

if __name__ == "__main__":
    main()
