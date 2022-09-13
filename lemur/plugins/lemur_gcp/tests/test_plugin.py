from unittest import mock
from lemur.plugins.lemur_gcp.plugin import GCPDestinationPlugin

name = "blah-localhost.com-localhost-20220830-20230830"

body = """
-----BEGIN CERTIFICATE-----
MIIB8TCCAZagAwIBAgIRAKyLS3e0aky5ru4i8k/fWC8wCgYIKoZIzj0EAwIwYjES
MBAGA1UEAwwJbG9jYWxob3N0MRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9z
MB4XDTIyMDgzMDE5MzM0MloXDTIzMDgzMDE5MzM0MlowazEbMBkGA1UEAwwSYmxh
aEBsb2NhbGhvc3QuY29tMRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9zMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVHkf6rYbpV1M7bPMFSbNxC6iHWm0HdvL
baHIjh6FD9O4asxa5TOs8Z8Lbg3hTUgFamznF34J3oYfEjgTxEO40aMkMCIwIAYD
VR0RAQH/BBYwFIISYmxhaEBsb2NhbGhvc3QuY29tMAoGCCqGSM49BAMCA0kAMEYC
IQDLz0FkXEkKyGXfkO0XQ6HwF0Tw+QirLNQDgrErZWmzbQIhAOiNDLODpdPzf+Aj
fQ6tr8edUIDueTN/LEqoDMlUX9up
-----END CERTIFICATE-----
"""

private_key = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH/TlH1MLEwUgPpZqd1EP3+9q792r7GsmecRQe6CknV4oAoGCCqGSM49
AwEHoUQDQgAEVHkf6rYbpV1M7bPMFSbNxC6iHWm0HdvLbaHIjh6FD9O4asxa5TOs
8Z8Lbg3hTUgFamznF34J3oYfEjgTxEO40Q==
-----END EC PRIVATE KEY-----
"""

cert_chain = """
-----BEGIN CERTIFICATE-----
MIIB7TCCAZSgAwIBAgIQBm3vFdgxR8e2GOGwpR+XTDAKBggqhkjOPQQDAjBiMRIw
EAYDVQQDDAlsb2NhbGhvc3QxFjAUBgNVBAoMDUV4YW1wbGUsIEluYy4xCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlMb3MgR2F0b3Mw
HhcNMjIwODI2MTkyMjMxWhcNNDIwODI2MTkyMjMxWjBiMRIwEAYDVQQDDAlsb2Nh
bGhvc3QxFjAUBgNVBAoMDUV4YW1wbGUsIEluYy4xCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlMb3MgR2F0b3MwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQhNX4vrw7MYlenuUfEU5TYvYgjHGeJfULwJeYomzMloKWQ
Msb0aRUWuEJ9STvqDSbHffK/Rm5BXAr328mzpIwRoywwKjAPBgNVHRMBAf8EBTAD
AQH/MBcGA1UdEQEB/wQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNHADBEAiB7
dmVGV4armOiIvo+cyuAN8PLr4mq4ByiVFWl9WQavpAIgRA0leVMbErRrz78EEZZR
aNVFrNhMcvbKB0eqb5VHL90=
-----END CERTIFICATE-----
"""

SUCCESS_INSERT_RESPONSE = {
    'kind': 'compute#operation',
    'id': '4927389014336055823',
    'name': 'operation-1661211870499-5e6dd077012f4-9b6e5e0d-ddfc98d2',
    'operationType': 'insert',
    'targetLink': 'https://www.googleapis.com/compute/v1/projects/testubg-sandbox/global/sslCertificates/test-cert-1234',
    'targetId': '8919843282434501135',
    'status': 'RUNNING',
    'user': 'lemur-test@test.iam.gserviceaccount.com',
    'progress': 0,
    'insertTime': '2022-08-22T16:44:32.218-07:00',
    'startTime': '2022-08-22T16:44:32.231-07:00',
}

options = [{
    'name': 'accountName',
    'type': 'str',
    'required': True,
    'value': 'lemur-test'
}]

@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin._insert_gcp_certificate", return_value=SUCCESS_INSERT_RESPONSE)
def test_upload(mock_sslCertificates):

    assert GCPDestinationPlugin().upload(
        name,
        body,
        private_key,
        cert_chain,
        options) == SUCCESS_INSERT_RESPONSE


@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin._get_gcp_credentials_from_vault", return_value="None")
def test_get_gcp_credentials(mock__get_gcp_credentials_from_vault):

    options = [{
        'name': 'Vault Path',
        'type': 'str',
        'required': True,
        'value': '/secret'
    }]
    import pdb; pdb.set_trace()

    assert GCPDestinationPlugin()._get_gcp_credentials(options) == None
