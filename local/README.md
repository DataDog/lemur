# Local Development Environment

This directory contains all configuration and scripts for local Lemur development.

## Quick Start

### Standard Setup
```bash
source .venv/bin/activate && make develop
cd local
docker-compose up -d
```

## Testing Scripts

```bash
# Create test certificates and destinations
docker exec -i local-lemur python3 /opt/lemur/local/testing/create_test_certs_and_destinations.py
```