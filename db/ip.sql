-- Table for IP metadata
CREATE TABLE ip_addresses (
    id VARCHAR(255) PRIMARY KEY, -- IP address (e.g., 185.189.112.27)
    type VARCHAR(50) NOT NULL, -- 'ip_address'
    last_analysis_date TIMESTAMP, -- Last VirusTotal analysis
    asn INTEGER, -- Autonomous System Number
    reputation INTEGER, -- Reputation score
    country VARCHAR(2), -- Country code (e.g., DE)
    as_owner VARCHAR(255), -- AS owner (e.g., M247 Europe SRL)
    regional_internet_registry VARCHAR(50), -- e.g., RIPE NCC
    network VARCHAR(50), -- e.g., 185.189.112.0/22
    whois_date TIMESTAMP, -- WHOIS data timestamp
    last_modification_date TIMESTAMP, -- Last modification
    continent VARCHAR(2), -- Continent code (e.g., EU)
    harmless_count INTEGER, -- From last_analysis_stats
    malicious_count INTEGER, -- From last_analysis_stats
    suspicious_count INTEGER, -- From last_analysis_stats
    undetected_count INTEGER, -- From last_analysis_stats
    timeout_count INTEGER, -- From last_analysis_stats
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for IP tags (many-to-one with ip_addresses)
CREATE TABLE ip_tags (
    id SERIAL PRIMARY KEY,
    ip_id VARCHAR(255) REFERENCES ip_addresses (id) ON DELETE CASCADE,
    tag VARCHAR(255), -- e.g., suspicious-udp
    UNIQUE (ip_id, tag)
);

-- Table for IP analysis results (many-to-one with ip_addresses)
CREATE TABLE ip_analysis_results (
    id SERIAL PRIMARY KEY,
    ip_id VARCHAR(255) REFERENCES ip_addresses (id) ON DELETE CASCADE,
    engine_name VARCHAR(100), -- e.g., BitDefender
    category VARCHAR(50), -- e.g., harmless, malicious
    result VARCHAR(50), -- e.g., clean, malware
    method VARCHAR(50), -- e.g., blacklist
    UNIQUE (ip_id, engine_name)
);

-- Table for additional IP JSONB data (WHOIS, votes)
CREATE TABLE ip_details (
    id SERIAL PRIMARY KEY,
    ip_id VARCHAR(255) UNIQUE REFERENCES ip_addresses (id) ON DELETE CASCADE,
    whois TEXT, -- Raw WHOIS text
    total_votes JSONB -- Store votes (harmless, malicious)
);

-- Indexes for performance
CREATE INDEX idx_ip_addresses_last_analysis_date ON ip_addresses (last_analysis_date);

CREATE INDEX idx_ip_addresses_reputation ON ip_addresses (reputation);

CREATE INDEX idx_ip_tags_ip_id ON ip_tags (ip_id);

CREATE INDEX idx_ip_analysis_results_ip_id ON ip_analysis_results (ip_id);

CREATE INDEX idx_ip_details_ip_id ON ip_details (ip_id);