from unittest import mock
from lemur.plugins.lemur_gcp.plugin import GCPDestinationPlugin

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


@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin._insert_gcp_certificate", return_value=SUCCESS_INSERT_RESPONSE)
def test_upload(mock_sslCertificates):
    assert GCPDestinationPlugin().upload(
        "test-cert-1234",
        "cert created for testing",
        "private_key",
        "certificate",
        "12345") == SUCCESS_INSERT_RESPONSE
