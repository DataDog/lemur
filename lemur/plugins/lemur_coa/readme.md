# Cert Orchestration Adapter Plugin

This plugin enables Lemur to upload and retrieve certificates from cross-DC Vault instances using the Cert Orchestration Adapter (COA) gRPC service.

## Destination

The destination plugin uploads certificates to Vault via the COA service. Certificates are stored with a naming convention that includes the common name, CA vendor, and key type (e.g., `*.example.com_DigiCert_RSA2048`).

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `audience` | str | Yes | Audience claim for the JWT used to authenticate with the COA service |
| `hostname` | str | Yes | Hostname of the COA service (must be a valid Fabric DNS name or `localhost`) |
| `port` | int | Yes | Port of the COA service |
| `paths` | str | Yes | Comma-delimited list of Vault paths to upload certificates to |
| `use_xdcgw` | bool | Yes | Whether to proxy requests through the Cross DC Gateway (default: True) |
| `use_ticino` | bool | Yes | Whether to use Ticino tokens for cross-DC ISA (default: False) |

## Source

The source plugin retrieves certificates from Vault via the COA service. It supports:
- Listing all certificates from configured paths
- Retrieving certificate by common name
- Discovering endpoints for certificate monitoring

### Configuration Options

Same as the destination plugin.

## Authentication

The plugin uses `dd_internal_authentication` for JWT-based authentication with the COA service. When `use_ticino` is enabled, it uses Ticino tokens for cross-DC internal service authentication.

## Testing Locally

Run the plugin tests:

```bash
pytest lemur/plugins/lemur_coa/tests/test_plugin.py -v
```

The tests use a mock gRPC server that stores certificates in-memory, so no external services are required.
