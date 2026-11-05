"""
lemur_salesforce — Lemur plugin for Salesforce Experience Cloud TLS certificates.

Covers three Lemur plugin types in one file:

  SalesforceIssuerPlugin      — intercepts Lemur's generated CSR, substitutes the
                                 Salesforce-generated one, then delegates signing to
                                 the existing DigiCertIssuerPlugin.

  SalesforceSourcePlugin      — polls Salesforce Metadata API for Certificate objects
                                 and returns them to Lemur inventory for expiry tracking.

  SalesforceDestinationPlugin — deploys the CA-signed cert back to Salesforce and
                                 updates the Experience Cloud domain binding.
                                 Sets requires_key=False (Salesforce holds the key).
                                 Sets sync_as_source=True so Lemur auto-syncs inventory
                                 without a separate source configuration.

Salesforce auth: JWT Bearer via Connected App — no user interaction, no token expiry.
Required config:
    SALESFORCE_CONSUMER_KEY   — Connected App consumer key
    SALESFORCE_PRIVATE_KEY    — PEM private key for the Connected App certificate
    SALESFORCE_USERNAME       — API-only service account username

Propagation note: Salesforce takes 4–8 hours to activate a deployed cert on a
custom domain. Lemur's default 35-day renewal window covers this. Emergency
same-day rotation is not possible.

Targets:
    partners.datadoghq.com   (Salesforce Partner Portal)
    govsupport.ddog-gov.com  (Salesforce Gov Cloud Support Portal)
"""

from flask import current_app

from lemur.plugins.base import plugins
from lemur.plugins.bases.issuer import IssuerPlugin
from lemur.plugins.bases.source import SourcePlugin
from lemur.plugins.bases.destination import DestinationPlugin

from . import VERSION
from . import sf_api


# ---------------------------------------------------------------------------
# IssuerPlugin
# ---------------------------------------------------------------------------

class SalesforceIssuerPlugin(IssuerPlugin):
    """Issue a cert by having Salesforce generate the CSR, then delegating
    signing to the existing DigiCertIssuerPlugin.

    Lemur calls create_certificate(lemur_generated_csr, issuer_options).
    We discard the Lemur-generated CSR entirely and substitute the
    Salesforce-generated one before handing off to DigiCert.
    """

    title = "Salesforce"
    slug = "salesforce-issuer"
    description = (
        "Issues certificates for Salesforce Experience Cloud custom domains. "
        "Salesforce generates the key pair and CSR; DigiCert signs it."
    )
    version = VERSION
    author = "Datadog Network Edge"
    author_url = "https://github.com/DataDog/lemur"

    options = [
        {
            "name": "orgUrl",
            "type": "str",
            "required": True,
            "helpMessage": "Salesforce org URL, e.g. https://datadoghq.my.salesforce.com",
        },
        {
            "name": "certDeveloperName",
            "type": "str",
            "required": True,
            "helpMessage": (
                "Developer name for the new Certificate object Salesforce will create. "
                "Must be unique per rotation — append a datestamp, e.g. partners_datadoghq_com_20270115."
            ),
        },
    ]

    def create_certificate(self, csr, issuer_options):
        """Create a cert: have Salesforce generate the CSR, sign it via DigiCert.

        :param csr: Lemur-generated CSR — intentionally ignored.
        :param issuer_options: dict of issuer options including orgUrl and certDeveloperName.
        :returns: (body, chain, external_id) tuple — same contract as DigiCertIssuerPlugin.
        """
        org_url = issuer_options.get("orgUrl") or current_app.config.get("SALESFORCE_ORG_URL")
        cert_name = issuer_options["certDeveloperName"]

        current_app.logger.info(
            f"salesforce_issuer: creating cert object '{cert_name}' in org {org_url}"
        )

        # 1. Tell Salesforce to generate a new key pair + CSR
        sf_api.create_ca_signed_cert(org_url, cert_name)

        # 2. Retrieve the Salesforce-generated CSR
        sf_csr = sf_api.get_csr(org_url, cert_name)
        current_app.logger.info(
            f"salesforce_issuer: retrieved CSR for '{cert_name}', delegating to DigiCert"
        )

        # 3. Delegate entirely to the existing DigiCert plugin — no new DigiCert code
        digicert = plugins.get("digicert-issuer")
        return digicert.create_certificate(sf_csr, issuer_options)
        # Returns (end_entity_pem, intermediate_pem, digicert_certificate_id)

    def get_ordered_certificate(self, pending_cert):
        """Poll DigiCert for async cert issuance — delegate entirely."""
        return plugins.get("digicert-issuer").get_ordered_certificate(pending_cert)

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        """Cancel a pending DigiCert order — delegate entirely."""
        return plugins.get("digicert-issuer").cancel_ordered_certificate(
            pending_cert, **kwargs
        )

    def revoke_certificate(self, certificate, reason):
        """Revocation: the cert lives in Salesforce; revoke at DigiCert level if needed.

        For MVP we do nothing here — the cert will naturally expire and Lemur
        will rotate it. Add DigiCert revocation call if required by policy.
        """
        current_app.logger.info(
            f"salesforce_issuer: revoke requested for {certificate.name} — "
            "no-op (Salesforce-hosted cert; revoke at DigiCert if required)"
        )

    @staticmethod
    def create_authority(options):
        """Register this plugin as a Lemur authority."""
        return (
            [],
            "",
            [{"name": "CN", "value": options.get("commonName", "Salesforce Issuer")}],
        )


# ---------------------------------------------------------------------------
# SourcePlugin
# ---------------------------------------------------------------------------

class SalesforceSourcePlugin(SourcePlugin):
    """Sync Salesforce Certificate metadata objects into Lemur inventory.

    Lemur calls get_certificates() on the configured poll schedule.
    The expirationDate field on the Certificate type drives Lemur's
    built-in expiry notifications — no custom alerting needed.
    """

    title = "Salesforce"
    slug = "salesforce-source"
    description = (
        "Discovers signed TLS certificates stored in Salesforce Certificate "
        "and Key Management, making them visible in Lemur inventory with "
        "expiry tracking."
    )
    version = VERSION
    author = "Datadog Network Edge"
    author_url = "https://github.com/DataDog/lemur"

    options = [
        {
            "name": "orgUrl",
            "type": "str",
            "required": True,
            "helpMessage": "Salesforce org URL, e.g. https://datadoghq.my.salesforce.com",
        },
    ]

    def get_certificates(self, options, **kwargs):
        """Return all signed Certificate objects from the Salesforce org.

        :returns: list of {"body": pem, "chain": None, "name": developer_name}
        """
        org_url = self.get_option("orgUrl", options)
        current_app.logger.debug(
            f"salesforce_source: syncing certificates from {org_url}"
        )
        return sf_api.list_certificates(org_url)

    def get_endpoints(self, options, **kwargs):
        """No Salesforce endpoint model — not applicable for MVP."""
        return []

    def clean(self, certificate, options, **kwargs):
        """Called when Lemur wants to remove a cert from this source — no-op."""
        pass


# ---------------------------------------------------------------------------
# DestinationPlugin
# ---------------------------------------------------------------------------

class SalesforceDestinationPlugin(DestinationPlugin):
    """Deploy a CA-signed cert back to Salesforce and update the domain binding.

    Key design decisions:
      requires_key = False   — Salesforce holds the private key; Lemur never sees it.
      sync_as_source = True  — Lemur will use SalesforceSourcePlugin to sync inventory
                               whenever this destination is synced. No separate source
                               configuration required.
    """

    title = "Salesforce"
    slug = "salesforce-destination"
    description = (
        "Deploys CA-signed TLS certificates to Salesforce Experience Cloud "
        "custom domains via Metadata API."
    )
    version = VERSION
    author = "Datadog Network Edge"
    author_url = "https://github.com/DataDog/lemur"

    requires_key = False          # Salesforce holds the private key
    sync_as_source = True         # DestinationPlugin doubles as a source
    sync_as_source_name = SalesforceSourcePlugin.slug

    options = [
        {
            "name": "orgUrl",
            "type": "str",
            "required": True,
            "helpMessage": "Salesforce org URL, e.g. https://datadoghq.my.salesforce.com",
        },
        {
            "name": "certDeveloperName",
            "type": "str",
            "required": True,
            "helpMessage": (
                "Developer name of the Certificate object to deploy the signed cert into. "
                "Must match the certDeveloperName used in the IssuerPlugin options."
            ),
        },
        {
            "name": "siteDeveloperName",
            "type": "str",
            "required": True,
            "helpMessage": (
                "Developer name or URL path prefix of the Experience Cloud Network/Site "
                "whose custom domain binding should be updated, "
                "e.g. partners or GovsupportPortal."
            ),
        },
        {
            "name": "domainName",
            "type": "str",
            "required": True,
            "helpMessage": (
                "Public hostname to probe after deployment, "
                "e.g. partners.datadoghq.com. Used for post-deploy TLS validation."
            ),
        },
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """Deploy the signed cert to Salesforce and update the domain binding.

        :param name: Lemur cert name (informational).
        :param body: PEM end-entity certificate.
        :param private_key: None — Salesforce holds the key; requires_key=False.
        :param cert_chain: PEM intermediate chain.
        :param options: plugin options dict.
        """
        org_url = self.get_option("orgUrl", options)
        cert_name = self.get_option("certDeveloperName", options)
        site_name = self.get_option("siteDeveloperName", options)
        domain = self.get_option("domainName", options)

        # Concatenate end-entity + chain into a single PEM bundle for Salesforce
        pem_bundle = body
        if cert_chain:
            pem_bundle = body.rstrip() + "\n" + cert_chain.strip()

        current_app.logger.info(
            f"salesforce_destination: deploying signed cert '{cert_name}' "
            f"to org {org_url}"
        )

        # 1. Upload signed cert back to Salesforce via Metadata API deploy
        deploy_id = sf_api.deploy_signed_cert(org_url, cert_name, pem_bundle)

        # 2. Update the Experience Cloud domain binding
        sf_api.update_site_cert_binding(org_url, site_name, cert_name)

        current_app.logger.info(
            f"salesforce_destination: cert '{cert_name}' deployed (deploy_id={deploy_id}). "
            f"Domain {domain} will serve the new cert in 4–8 hours."
        )
