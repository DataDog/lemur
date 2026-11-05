"""
Salesforce Metadata API client for Lemur certificate management.

Handles JWT Bearer auth and the three Metadata API operations needed
for cert rotation:
  1. create_ca_signed_cert   — triggers Salesforce to generate a new key pair + CSR
  2. get_csr                 — retrieves the PEM CSR from the new cert object
  3. deploy_signed_cert      — uploads the CA-signed chain back to Salesforce
  4. update_site_cert_binding — updates CustomSite to reference the new cert
  5. list_certificates       — enumerates all Certificate metadata objects (for SourcePlugin)
"""

import base64
import time
import zipfile
import io

import jwt
import requests
from flask import current_app


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _get_access_token(org_url, consumer_key, private_key_pem):
    """Obtain a Salesforce access token via JWT Bearer flow.

    No user interaction required; token is valid for ~1 hour.
    Callers should cache and refresh as needed (Lemur plugin __init__ is
    called per-request so we keep this simple and re-auth each call for MVP).
    """
    audience = "https://login.salesforce.com"
    if "sandbox" in org_url or "test" in org_url:
        audience = "https://test.salesforce.com"

    now = int(time.time())
    payload = {
        "iss": consumer_key,
        "sub": current_app.config.get("SALESFORCE_USERNAME"),
        "aud": audience,
        "exp": now + 300,
    }
    assertion = jwt.encode(payload, private_key_pem, algorithm="RS256")

    resp = requests.post(
        f"{audience}/services/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _session(org_url):
    """Return an authenticated requests.Session for the given org."""
    consumer_key = current_app.config["SALESFORCE_CONSUMER_KEY"]
    private_key_pem = current_app.config["SALESFORCE_PRIVATE_KEY"]

    token = _get_access_token(org_url, consumer_key, private_key_pem)
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}"})
    return s


# ---------------------------------------------------------------------------
# Metadata API helpers
# ---------------------------------------------------------------------------

_API = "{org_url}/services/Soap/m/59.0"  # Metadata API SOAP endpoint

# We use the REST-flavoured Tooling API for reads and the Metadata REST API
# for deploys, which is simpler than raw SOAP in Python.
_TOOLING = "{org_url}/services/data/v59.0/tooling"
_REST = "{org_url}/services/data/v59.0"


def create_ca_signed_cert(org_url, cert_developer_name, master_label=None):
    """Create a new CA-signed Certificate metadata object.

    Salesforce generates the RSA key pair and CSR internally.
    The returned cert object's .crt content IS the PEM CSR until
    a signed certificate is uploaded back.

    Raises on failure.
    """
    session = _session(org_url)
    label = master_label or cert_developer_name.replace("_", " ")

    # Use Tooling API sObject to create the Certificate record
    url = f"{_TOOLING.format(org_url=org_url)}/sobjects/Certificate"
    payload = {
        "DeveloperName": cert_developer_name,
        "MasterLabel": label,
        "KeySize": 2048,
        "ExpirationDate": None,  # set by CA after signing
        "IsPrivateKeyExportable": False,
    }
    resp = session.post(url, json=payload, timeout=30)
    if resp.status_code not in (200, 201):
        raise Exception(
            f"Failed to create Salesforce cert '{cert_developer_name}': "
            f"{resp.status_code} {resp.text}"
        )
    current_app.logger.info(
        f"salesforce_plugin: created cert object '{cert_developer_name}'"
    )
    return resp.json()["id"]


def get_csr(org_url, cert_developer_name):
    """Retrieve the PEM CSR from a newly created CA-signed cert object.

    Before a signed cert is uploaded, the Certificate body field contains
    the Salesforce-generated CSR in PEM format.

    Returns the CSR as a string.
    """
    session = _session(org_url)

    # Query by DeveloperName to get the record Id and Body
    query = (
        f"SELECT Id, DeveloperName, Body FROM Certificate "
        f"WHERE DeveloperName = '{cert_developer_name}'"
    )
    url = f"{_TOOLING.format(org_url=org_url)}/query"
    resp = session.get(url, params={"q": query}, timeout=30)
    resp.raise_for_status()

    records = resp.json().get("records", [])
    if not records:
        raise Exception(
            f"Salesforce cert '{cert_developer_name}' not found via Tooling API"
        )

    body = records[0].get("Body", "")
    if not body or "BEGIN CERTIFICATE REQUEST" not in body:
        raise Exception(
            f"Salesforce cert '{cert_developer_name}' body does not contain a CSR. "
            "Has a signed cert already been uploaded?"
        )
    return body


def deploy_signed_cert(org_url, cert_developer_name, signed_pem_chain):
    """Upload a signed certificate chain back to Salesforce via Metadata API deploy.

    signed_pem_chain should be the end-entity cert + intermediate(s) concatenated.
    Salesforce activates the cert on the custom domain 4–8 hours after deploy.
    """
    session = _session(org_url)

    # Build a minimal Metadata API deploy ZIP:
    # certificates/<DeveloperName>.crt  (the signed PEM chain)
    # package.xml
    package_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Package xmlns="http://soap.sforce.com/2006/04/metadata">
    <types>
        <members>{cert_developer_name}</members>
        <name>Certificate</name>
    </types>
    <version>59.0</version>
</Package>"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("package.xml", package_xml)
        zf.writestr(f"certificates/{cert_developer_name}.crt", signed_pem_chain)
    buf.seek(0)

    deploy_url = f"{_REST.format(org_url=org_url)}/metadata/deployRequest"
    resp = session.post(
        deploy_url,
        files={"file": ("deploy.zip", buf, "application/zip")},
        data={"deployOptions": '{"singlePackage": true}'},
        timeout=60,
    )
    if resp.status_code not in (200, 201):
        raise Exception(
            f"Salesforce deploy failed for '{cert_developer_name}': "
            f"{resp.status_code} {resp.text}"
        )

    deploy_id = resp.json().get("id")
    current_app.logger.info(
        f"salesforce_plugin: deploy started for '{cert_developer_name}', "
        f"deploy_id={deploy_id}. Cert active in 4–8h."
    )
    return deploy_id


def update_site_cert_binding(org_url, site_developer_name, cert_developer_name):
    """Update the CustomSite/ExperienceBundle domain binding to use the new cert.

    Uses Tooling API to patch the SiteDotCom or Network record's
    custom domain certificate reference.

    MVP: logs the required manual step if automated binding is not available.
    """
    session = _session(org_url)

    # Query for the Network (Experience Cloud site) by DeveloperName
    query = (
        f"SELECT Id, Name, SslCertificateId FROM Network "
        f"WHERE UrlPathPrefix = '{site_developer_name}' OR Name = '{site_developer_name}'"
    )
    url = f"{_TOOLING.format(org_url=org_url)}/query"
    resp = session.get(url, params={"q": query}, timeout=30)
    resp.raise_for_status()

    records = resp.json().get("records", [])
    if not records:
        # Domain binding update may require Setup UI or a Metadata deploy of
        # the CustomSite record — log for operator and continue.
        current_app.logger.warning(
            f"salesforce_plugin: could not find Network record for site "
            f"'{site_developer_name}'. Domain binding may need manual update in "
            f"Salesforce Setup → Digital Experiences → Domains."
        )
        return

    network_id = records[0]["Id"]

    # Look up the Certificate Id by developer name
    cert_query = (
        f"SELECT Id FROM Certificate WHERE DeveloperName = '{cert_developer_name}'"
    )
    cert_resp = session.get(url, params={"q": cert_query}, timeout=30)
    cert_resp.raise_for_status()
    cert_records = cert_resp.json().get("records", [])
    if not cert_records:
        raise Exception(
            f"Cannot find deployed cert '{cert_developer_name}' to bind to site"
        )
    cert_id = cert_records[0]["Id"]

    patch_url = f"{_TOOLING.format(org_url=org_url)}/sobjects/Network/{network_id}"
    patch_resp = session.patch(
        patch_url, json={"SslCertificateId": cert_id}, timeout=30
    )
    if patch_resp.status_code not in (200, 204):
        raise Exception(
            f"Failed to update cert binding for site '{site_developer_name}': "
            f"{patch_resp.status_code} {patch_resp.text}"
        )
    current_app.logger.info(
        f"salesforce_plugin: updated site '{site_developer_name}' "
        f"to use cert '{cert_developer_name}'"
    )


def list_certificates(org_url):
    """List all Certificate metadata objects in the org.

    Returns a list of dicts compatible with Lemur's SourcePlugin.get_certificates
    return contract: [{"body": pem, "chain": None, "name": str}]

    Only returns signed certs (body contains BEGIN CERTIFICATE, not a CSR).
    Unsigned/pending CSR-only cert objects are skipped.
    """
    session = _session(org_url)

    query = "SELECT DeveloperName, Body, ExpirationDate FROM Certificate"
    url = f"{_TOOLING.format(org_url=org_url)}/query"

    certs = []
    next_url = url
    params = {"q": query}

    while True:
        resp = session.get(next_url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for record in data.get("records", []):
            body = record.get("Body", "")
            # Skip cert objects that still only contain a CSR (not yet signed)
            if not body or "BEGIN CERTIFICATE\n" not in body:
                continue
            certs.append({
                "body": body,
                "chain": None,  # Salesforce stores chain concatenated in Body
                "name": record["DeveloperName"],
            })

        if data.get("done", True):
            break
        next_url = org_url + data["nextRecordsUrl"]
        params = {}

    return certs
