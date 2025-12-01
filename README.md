# MailIntelKit

Quick start:
- Create venv: `python -m venv .venv`
- Install: `pip install -r requirements.txt`
- CLI: `python email_security_check.py example.com`
- API: `uvicorn email_security_check.api:app --reload --port 5000`
- Docker: `docker build -t email-security-check . && docker run -p 5000:5000 email-security-check`

This project provides a comprehensive tool for checking email authentication mechanisms, specifically SPF, DKIM, and DMARC records. It is designed for cybersecurity professionals and developers who need to assess the email security posture of domains.

## Features

- Extracts and processes SPF, DKIM, and DMARC records.
- Command-line interface for easy usage.
- API endpoints for integration with web applications.
- Utility functions for DNS queries related to email security.

## Project Structure

```
email-security-check
├── src
│   ├── email_security_check
│   │   ├── __init__.py
│   │   ├── core.py          # Core logic for email security checks
│   │   ├── cli.py           # Command-line interface implementation
│   │   ├── api.py           # API endpoints for email security checks
│   │   ├── dns_utils.py     # Utility functions for DNS queries
│   │   └── models.py        # Data models for SPF, DKIM, and DMARC
│   └── scripts
│       └── email_security_check.py  # Original script for running checks
├── tests
│   ├── test_core.py         # Unit tests for core functionality
│   └── test_api.py          # Unit tests for API endpoints
├── Dockerfile                # Docker image build instructions
├── .dockerignore             # Files to ignore when building Docker image
├── pyproject.toml           # Project configuration and dependencies
├── requirements.txt          # Python dependencies
├── .gitignore                # Files to ignore in version control
└── README.md                 # Project documentation
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd email-security-check
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Command-Line Interface

To run the email security check from the command line, use:
```
python src/scripts/email_security_check.py <domain>
```

### API

Run the API server (from the project root):
```
uvicorn src.email_security_check.api:app --reload --port 5000
```

Available routes

- GET /health
   - Description: basic health check
   - Example: 
      ```   
      curl http://localhost:5000/health
      ```
- POST /report
   - Description: run full checks (SPF, DKIM, DMARC) for a domain. Use JSON body { "domain": "example.com", "aggressive_dkim": true }
   - Example:
      ```
      curl -X POST http://localhost:5000/report \
         -H "Content-Type: application/json" \
         -d '{"domain":"example.com"}'
      ```
- GET /spf/{domain}
   - Description: fetch and parse SPF record(s), show parsed details and estimated DNS-lookup count
   - Example: 
      ```
      curl http://localhost:5000/spf/example.com
      ```
- GET /dkim/{domain}
   - Description: fetch DKIM selector records discovered by heuristics. Query params:
      - selector: (optional) check a specific selector
      - aggressive: (optional) use an expanded selector list when discovering
   - Examples:
      ```
      curl http://localhost:5000/dkim/example.com
      curl "http://localhost:5000/dkim/example.com?selector=default"
      curl "http://localhost:5000/dkim/example.com?aggressive=true"
      ```
- GET /dmarc/{domain}
   - Description: fetch DMARC TXT record and parsed tags
   - Example: 
      ```
      curl http://localhost:5000/dmarc/example.com
      ```

## Docker

To build the Docker image, run:
```
docker build -t email-security-check .
```

To run the Docker container:
```
docker run -p 5000:5000 email-security-check
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
