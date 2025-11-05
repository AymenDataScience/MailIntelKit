# Email security check

Quick start:
- Create venv: `python -m venv .venv`
- Install: `pip install -r requirements.txt`
- CLI: `python email_security_check.py example.com`
- API: `uvicorn email_security_check.api:app --reload --port 8080`
- Docker: `docker build -t email-security-check . && docker run -p 8080:8080 email-security-check`

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

The API can be accessed at the specified endpoints (to be defined in `api.py`). 

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