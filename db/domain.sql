-- Table for domain metadata
CREATE TABLE domains (
    id VARCHAR(255) PRIMARY KEY, -- Domain name (e.g., google.com)
    type VARCHAR(50) NOT NULL, -- 'domain'
    creation_date TIMESTAMP, -- Domain creation date
    expiration_date TIMESTAMP, -- Domain expiration date
    last_analysis_date TIMESTAMP, -- Last VirusTotal analysis
    reputation INTEGER, -- Reputation score
    registrar VARCHAR(255), -- Registrar name
    tld VARCHAR(50), -- Top-level domain
    whois_date TIMESTAMP, -- WHOIS data timestamp
    harmless_count INTEGER, -- From last_analysis_stats
    malicious_count INTEGER, -- From last_analysis_stats
    suspicious_count INTEGER, -- From last_analysis_stats
    undetected_count INTEGER, -- From last_analysis_stats
    timeout_count INTEGER, -- From last_analysis_stats
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for categories (many-to-one with domains)
CREATE TABLE domain_categories (
    id SERIAL PRIMARY KEY,
    domain_id VARCHAR(255) REFERENCES domains (id) ON DELETE CASCADE,
    engine_name VARCHAR(100), -- e.g., BitDefender
    category VARCHAR(255), -- e.g., searchengines
    UNIQUE (domain_id, engine_name)
);

-- Table for analysis results (many-to-one with domains)
CREATE TABLE domain_analysis_results (
    id SERIAL PRIMARY KEY,
    domain_id VARCHAR(255) REFERENCES domains (id) ON DELETE CASCADE,
    engine_name VARCHAR(100), -- e.g., BitDefender
    category VARCHAR(50), -- e.g., harmless, undetected
    result VARCHAR(50), -- e.g., clean, unrated
    method VARCHAR(50), -- e.g., blacklist
    UNIQUE (domain_id, engine_name)
);

-- Table for additional JSONB data (DNS records, HTTPS certificate, RDAP, etc.)
CREATE TABLE domain_details (
    id SERIAL PRIMARY KEY,
    domain_id VARCHAR(255) UNIQUE REFERENCES domains (id) ON DELETE CASCADE,
    last_dns_records JSONB, -- Store DNS records
    last_https_certificate JSONB, -- Store certificate details
    rdap JSONB, -- Store RDAP data
    whois TEXT, -- Store WHOIS raw text
    popularity_ranks JSONB, -- Store popularity ranks
    total_votes JSONB -- Store votes (harmless, malicious)
);

-- Table for caching (optional, if in-memory caching like Redis is not used)
CREATE TABLE domain_cache (
    id VARCHAR(255) PRIMARY KEY, -- Domain name
    data JSONB, -- Cached API response or subset
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_domains_last_analysis_date ON domains (last_analysis_date);

CREATE INDEX idx_domains_reputation ON domains (reputation);

CREATE INDEX idx_domain_categories_domain_id ON domain_categories (domain_id);

CREATE INDEX idx_domain_analysis_results_domain_id ON domain_analysis_results (domain_id);

CREATE INDEX idx_domain_details_domain_id ON domain_details (domain_id);

CREATE INDEX idx_domain_cache_expires_at ON domain_cache (expires_at);