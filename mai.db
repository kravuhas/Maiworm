-- Scans de segurança
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    scan_type TEXT,
    target TEXT,
    timestamp TEXT,
    score REAL,
    result_json TEXT,
    status TEXT
);

-- Vulnerabilidades encontradas
CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    title TEXT,
    description TEXT,
    level TEXT,
    cwe TEXT,
    owasp_category TEXT,
    remediation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Notícias de segurança
CREATE TABLE news (
    id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    source TEXT,
    url TEXT,
    published TEXT,
    risk_level TEXT,
    fetched_at TEXT,
    UNIQUE(url)
);

-- Análises RAG
CREATE TABLE rag_analyses (
    id TEXT PRIMARY KEY,
    document_path TEXT,
    query TEXT,
    response TEXT,
    sources TEXT,
    timestamp TEXT
);

-- Cache
CREATE TABLE cache (
    key TEXT PRIMARY KEY,
    value TEXT,
    expires_at TEXT
);