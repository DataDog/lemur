from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates, target_https_proxies, global_forwarding_rules, \
    ssl_policies
from google.cloud.compute_v1 import TargetHttpsProxiesSetSslCertificatesRequest
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
import hvac
import os

from lemur.common.utils import parse_certificate, split_pem
from lemur.common.defaults import common_name, issuer, not_before
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins import lemur_gcp as gcp


class GCPDestinationPlugin(DestinationPlugin):
    title = "GCP"
    slug = "gcp-destination"
    version = gcp.VERSION
    description = "Allow the uploading of certificates to GCP"
    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

    options = [
        {
            "name": "projectID",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project ID",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "required": True,
            "available": ["vault", "serviceAccountToken"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "vaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        },
        {
            "name": "serviceAccountTokenPath",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        }
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        try:
            ssl_certificate_body = {
                "name": self._certificate_name(body),
                "certificate": self._full_ca(body, cert_chain),
                "description": "",
                "private_key": private_key,
            }
            credentials = self._get_gcp_credentials(options)
            return self._insert_gcp_certificate(
                self.get_option("projectID", options),
                ssl_certificate_body,
                credentials,
            )

        except Exception as e:
            current_app.logger.error(
                f"Issue with uploading {name} to GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue uploading certificate to GCP: {e}")

    def _insert_gcp_certificate(self, project_id, ssl_certificate_body, credentials):
        return ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )

    def _get_gcp_credentials(self, options):
        if self.get_option('authenticationMethod', options) == "vault":
            # make a request to vault for GCP token
            return self._get_gcp_credentials_from_vault(options)
        elif self.get_option('authenticationMethod', options) == "serviceAccountToken":
            if self.get_option('serviceAccountTokenPath', options) is not None:
                return service_account.Credentials.from_service_account_file(
                    self.get_option('serviceAccountTokenPath', options)
                )

        raise Exception("No supported way to authenticate with GCP")

    def _get_gcp_credentials_from_vault(self, options):
        service_token = hvac.Client(os.environ['VAULT_ADDR']) \
            .secrets.gcp \
            .generate_oauth2_access_token(
            roleset="",
            mount_point=f"{self.get_option('vaultMountPoint', options)}"
        )["data"]["token"].rstrip(".")

        credentials = Credentials(service_token)

        return credentials

    def _certificate_name(self, body):
        """
        We need to change the name of the certificate that we are uploading to comply with GCP naming standards.
        The cert name will follow the convention "ssl-{Cert CN}-{Date Issued}-{Issuer}"
        """
        cert = parse_certificate(body)
        cn = common_name(cert)
        authority = issuer(cert)
        issued_on = not_before(cert).date()

        cert_name = f"ssl-{cn}-{authority}-{issued_on}"

        return self._modify_cert_name_for_gcp(cert_name)

    def _modify_cert_name_for_gcp(self, cert_name):
        # Modify the cert name to comply with GCP naming convention
        gcp_name = cert_name.replace('.', '-')
        gcp_name = gcp_name.replace('*', "star")
        gcp_name = gcp_name.lower()
        gcp_name = gcp_name[:63]
        gcp_name = gcp_name.rstrip('.*-')

        return gcp_name

    def _full_ca(self, body, cert_chain):
        # in GCP you need to assemble the cert body and the cert chain in the same parameter
        return f"{body}\n{cert_chain}"


class GCPSourcePlugin(SourcePlugin):
    title = "GCP"
    slug = "gcp-source"
    description = "Discovers all SSL certificates and HTTPs target proxies (global)"
    version = gcp.VERSION

    author = "Henry Wang"
    author_url = "https://github.com/Datadog/lemur"

    options = [
        {
            "name": "projectID",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project ID",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "required": True,
            "available": ["vault", "serviceAccountToken"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "vaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        },
        {
            "name": "serviceAccountTokenPath",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        }
    ]

    def get_certificates(self, options, **kwargs):
        try:
            credentials = self._get_gcp_credentials(options)
            project_id = self.get_option("projectID", options)
            client = ssl_certificates.SslCertificatesClient(credentials=credentials)
            pager = client.list(project=project_id)
            certs = []
            for cert_meta in pager:
                try:
                    if cert_meta.type_ != "SELF_MANAGED":
                        continue
                    chain = []
                    # Skip CSR if it's part of the certificate returned by the GCP API.
                    for cert in split_pem(cert_meta.certificate):
                        if '-----BEGIN CERTIFICATE-----' in cert:
                            chain.append(cert)
                    if not chain:
                        continue
                    certs.append(dict(
                        body=chain[0],
                        chain="\n".join(chain[1:]),
                        name=cert_meta.name,
                    ))
                except Exception as e:
                    current_app.logger.error(
                        f"Issue with fetching certificate {cert_meta.name} from GCP. Action failed with the following "
                        f"log: {e}",
                        exc_info=True,
                    )
            return certs
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificates from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching certificates from GCP: {e}")

    def get_certificate_by_name(self, certificate_name, options):
        try:
            credentials = self._get_gcp_credentials(options)
            project_id = self.get_option("projectID", options)
            client = ssl_certificates.SslCertificatesClient(credentials=credentials)
            cert_meta = client.get(project=project_id, ssl_certificate=certificate_name)
            if cert_meta:
                chain = []
                # Skip CSR if it's part of the certificate returned by the GCP API.
                for cert in split_pem(cert_meta.certificate):
                    if '-----BEGIN CERTIFICATE-----' in cert:
                        chain.append(cert)
                return dict(
                    body=chain[0],
                    chain="\n".join(chain[1:]),
                    name=cert_meta.name,
                )
            return None
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificate by name from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching certificate from GCP: {e}")

    def get_endpoints(self, options, **kwargs):
        try:
            credentials = self._get_gcp_credentials(options)
            project_id = self.get_option("projectID", options)
            forwarding_rules_client = global_forwarding_rules.GlobalForwardingRulesClient(credentials=credentials)
            forwarding_rules_map = defaultdict(list)
            # Multiple forwarding rules can reference the same target proxy
            # Construct a mapping of targets -> list of forwarding rules that use the target
            for rule in forwarding_rules_client.list(project=project_id):
                forwarding_rules_map[rule.target].append(rule)
            print('map=', forwarding_rules_map)
            proxies_client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
            ssl_policies_client = ssl_policies.SslPoliciesClient(credentials=credentials)
            ssl_client = ssl_certificates.SslCertificatesClient(credentials=credentials)
            pager = proxies_client.list(project=project_id)
            endpoints = []
            for i, target_proxy in enumerate(pager):
                if len(target_proxy.ssl_certificates) == 0:
                    continue
                fw_rules = forwarding_rules_map.get(target_proxy.self_link, None)
                if not fw_rules:
                    continue
                # The first certificate is the primary.
                # See https://cloud.google.com/sdk/gcloud/reference/compute/target-https-proxies/update
                ssl_cert_name = get_name_from_self_link(target_proxy.ssl_certificates[0])
                cert = ssl_client.get(project=project_id, ssl_certificate=ssl_cert_name)
                primary_certificate = dict(
                    name=cert.name,
                    registry_type="targethttpsproxy",
                    path="",
                )
                fw_rule_ips = sorted([fw_rule.I_p_address for fw_rule in fw_rules])
                endpoint = dict(
                    name=target_proxy.name,
                    type="targethttpsproxy",
                    primary_certificate=primary_certificate,
                    dnsname=fw_rule_ips[0],
                    port=443,
                    policy=dict(
                        name="",
                        ciphers=[],
                    ),
                )
                if len(fw_rule_ips) > 1:
                    endpoint["aliases"] = fw_rule_ips[1:]
                if target_proxy.ssl_policy:
                    policy = ssl_policies_client.get(
                        project=project_id,
                        ssl_policy=get_name_from_self_link(target_proxy.ssl_policy))
                    endpoint["policy"] = format_ssl_policy(policy)
                endpoints.append(endpoint)
            return endpoints
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching endpoints from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching endpoints from GCP: {e}")

    def update_endpoint(self, endpoint, certificate):
        print('endpoint=', endpoint)
        print('certificate=', certificate)
        options = endpoint.source.options
        credentials = self._get_gcp_credentials(options)
        project_id = self.get_option("projectID", options)
        proxies_client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
        proxy = proxies_client.get(
            project=project_id,
            target_https_proxy=endpoint.source.name,
        )
        if len(proxy.ssl_certificates) > 1:
            current_app.logger.warning("Skipping endpoint which has multiple SSL certificates")
            return
        ssl_certs = proxy.ssl_certificates
        print('ssl_certs=', ssl_certs)
        if ssl_certs:
            return
        proxies_client.set_ssl_certificates(
            project=project_id,
            target_https_proxy=proxy.name,
            target_https_proxies_set_ssl_certificates_request_resource=TargetHttpsProxiesSetSslCertificatesRequest(
                ssl_certificates=[certificate]
            ),
        )

    def clean(self, certificate, options, **kwargs):
        raise NotImplementedError

    def _get_gcp_credentials(self, options):
        if self.get_option('authenticationMethod', options) == "vault":
            # make a request to vault for GCP token
            return self._get_gcp_credentials_from_vault(options)
        elif self.get_option('authenticationMethod', options) == "serviceAccountToken":
            if self.get_option('serviceAccountTokenPath', options) is not None:
                return service_account.Credentials.from_service_account_file(
                    self.get_option('serviceAccountTokenPath', options)
                )

        raise Exception("No supported way to authenticate with GCP")

    def _get_gcp_credentials_from_vault(self, options):
        service_token = hvac.Client(os.environ['VAULT_ADDR']) \
            .secrets.gcp \
            .generate_oauth2_access_token(
            roleset="",
            mount_point=f"{self.get_option('vaultMountPoint', options)}"
        )["data"]["token"].rstrip(".")

        credentials = Credentials(service_token)

        return credentials


def get_name_from_self_link(self_link):
    return self_link.split('/')[-1]


def format_ssl_policy(policy):
    """
    Format cipher policy information for an HTTPs target proxy into a common format.
    :param policy:
    :return:
    """
    if not policy:
        return dict(name='', ciphers=[])
    return dict(name=policy.name, ciphers=[cipher for cipher in policy.enabled_features])
