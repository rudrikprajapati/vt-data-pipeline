## Project Overview

The purpose of this project is to fetch domain and IP address reports from the VirusTotal API, store the data in a structured way in a database, and cache responses to improve performance. The system is built using Go for the backend API, PostgreSQL for persistent storage, and Redis for caching. It supports querying domain and IP reports via a RESTful API endpoint and ensures data consistency using database transactions and parallel processing where possible.

## Thought Process and Design Decisions

### Database Design

To store the data efficiently, I decided to split the information into multiple tables based on its nature and relationships. My reasoning was to keep frequently accessed metadata in primary tables, store related data (like categories or tags) in separate tables with foreign keys, and use JSONB for complex or less frequently queried data. This approach ensures flexibility and performance. The database schema can be further customized based on specific needs, such as adding more tables or fields.

#### Domain Data

- **Metadata**: The `domains` table stores core information like domain name, creation date, expiration date, reputation, registrar, TLD, and analysis stats (harmless, malicious, etc.). This table is optimized for quick lookups of key domain details.
- **Categories**: The `domain_categories` table stores engine-specific categories (e.g., BitDefender: "searchengines") with a foreign key to `domains`. This allows multiple categories per domain.
- **Analysis Results**: The `domain_analysis_results` table stores engine-specific analysis results (e.g., category, result, method) with a foreign key to `domains`. This supports multiple analysis results per domain.
- **Details**: The `domain_details` table stores complex data like DNS records, HTTPS certificates, RDAP, WHOIS text, popularity ranks, and votes in JSONB or TEXT format. This reduces the need for multiple tables for less structured data.
- **Cache**: Initially, I planned to use a `domain_cache` table to store cached API responses, but I later switched to Redis (explained below).

#### IP Address Data

- **Metadata**: The `ip_addresses` table stores core IP details like IP address, ASN, reputation, country, AS owner, network, and analysis stats. It’s designed similarly to the `domains` table but tailored for IP-specific fields.
- **Tags**: The `ip_tags` table stores tags (e.g., "suspicious-udp") with a foreign key to `ip_addresses`, supporting multiple tags per IP.
- **Analysis Results**: The `ip_analysis_results` table stores engine-specific analysis results for IPs, similar to `domain_analysis_results`.
- **Details**: The `ip_details` table stores WHOIS text and votes in JSONB format, keeping the schema simple for IP-specific details.

I added indexes on frequently queried fields (e.g., `last_analysis_date`, `reputation`) to improve query performance. The use of foreign keys with `ON DELETE CASCADE` ensures data consistency when records are deleted.

### Technology Choices

- **Database**: I initially chose Neon, a hosted PostgreSQL service, for its scalability and ease of use in a cloud environment. Later, I switched to a local PostgreSQL instance running in Docker for development flexibility. PostgreSQL was ideal due to its support for JSONB, transactions, and robust querying capabilities.
- **Backend**: I used Go with the Gin framework for the API because Go is fast, has great concurrency support (goroutines), and is well-suited for building RESTful APIs. Gin simplifies routing and request handling.
- **Caching**: Initially, I designed a `domain_cache` table with a Least Recently Used (LRU) mechanism and a capacity of 5 entries, each expiring after 1 hour. The idea was to check the cache first, fetch from VirusTotal if the cache was expired or missing, update the database and cache, and remove the oldest entry if the cache was full. Later, I replaced this with Redis, a fast in-memory cache, also running in Docker. Redis simplifies caching with built-in expiration (1 hour) and eliminates the need for manual LRU logic.

### Caching Strategy

The caching mechanism is designed to reduce VirusTotal API calls, which have rate limits (4 requests/minute in the free tier). Here’s how it works:

1. When a request for a domain or IP report is received, the system checks Redis using a key (e.g., `domain:google.com` or `ip:185.189.112.27`).
2. If the data exists and isn’t expired, it’s returned immediately.
3. If the data is expired or missing, the system fetches the report from VirusTotal, updates the database, and caches the result in Redis with a 1-hour expiration.
4. Redis automatically handles expiration, so no manual cleanup is needed.

### Data Processing and Transactions

To ensure data consistency, I used database transactions for all write operations (saving metadata, details, categories/tags, and analysis results). This guarantees that either all data is saved or none is, preventing partial updates. For example, if saving analysis results fails, the transaction is rolled back, and no changes are applied.

To improve performance, I used Go goroutines for parallel operations where possible, such as saving categories/tags and analysis results. These operations are independent, so running them concurrently reduces the total processing time. I used a `WaitGroup` to synchronize goroutines and an error channel to collect any errors, ensuring robust error handling.

### API Design

The API exposes a single endpoint, `GET /report/:id?type=<domains|ip_addresses>`, to fetch reports. The `id` parameter is the domain (e.g., `google.com`) or IP address (e.g., `185.189.112.27`), and the `type` query parameter specifies the report type. The response includes the main entity (domain or IP), related data (categories/tags, analysis results), and details (WHOIS, votes, etc.). The handler validates the `type` parameter and calls the appropriate service function (`FetchDomainVTReport` or `FetchIPReport`).

## Implementation Details

- **Directory Structure**: The codebase is organized into packages:
  - `services`: Contains logic for fetching and processing VirusTotal reports.
  - `repositories`: Handles database operations (e.g., saving domains, IPs, and related data).
  - `models`: Defines structs for domains, IPs, and API responses.
  - `redis`: Manages Redis cache interactions.
  - `config`: Loads configuration (e.g., VirusTotal API key).
  - `handlers`: Defines API endpoints using Gin.
- **Concurrency**: Goroutines are used in the service layer to save categories/tags and analysis results in parallel, improving performance.
- **Error Handling**: Comprehensive logging is implemented to track cache hits/misses, API calls, database operations, and errors. Errors are propagated to the handler, which returns appropriate HTTP status codes (e.g., 400 for invalid `type`, 500 for server errors).
- **Docker Setup**: PostgreSQL and Redis run in Docker containers for local development, making it easy to spin up the environment with `docker-compose`.
