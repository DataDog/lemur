from unittest import mock

from lemur.plugins.lemur_gcp import certificates
from lemur.plugins.lemur_gcp.auth import get_gcp_credentials
from lemur.plugins.lemur_gcp.plugin import GCPDestinationPlugin
from google.cloud.compute_v1 import types

name = "ssl-test-localhost-com-localhost-2022-08-30"
token = "ya29.c.b0AXv0zTN36HtXN2cJolg9tAj0vGAOT29FF-WNxQzvPu"
body = """
-----BEGIN CERTIFICATE-----
MIIB7zCCAZagAwIBAgIRAILPQ22P50KYnufSOcyC3xgwCgYIKoZIzj0EAwIwYjES
MBAGA1UEAwwJbG9jYWxob3N0MRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9z
MB4XDTIyMDgzMDE2MzkwN1oXDTIzMDgzMDE2MzkwN1owazEbMBkGA1UEAwwSdGVz
dC5sb2NhbGhvc3QuY29tMRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9zMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4FP/xJlvy7jDFRbElv7opDMFF0Tw7jSr
S03Nyh8//spXeNPIvu49uknYsJiMtC19OW8GsH4FXxAMarmLsuUaraMkMCIwIAYD
VR0RAQH/BBYwFIISdGVzdC5sb2NhbGhvc3QuY29tMAoGCCqGSM49BAMCA0cAMEQC
IHDfzhvpCm37SjMbJUY0hbAs+hXYIayNjCZaOvl5gQUEAiAuZ93rbdEZ69Tzd/iN
I/Wm13nhSNDgVeEWbr3BP1ZacQ==
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

options = [
    {
        'name': 'projectID',
        'type': 'str',
        'required': True,
        'value': 'lemur-test'
    },
    {
        'name': 'region',
        'type': 'str',
        'value': 'europe-west3'
    },
    {
        'name': 'authenticationMethod',
        'type': 'str',
        'required': True,
        'value': 'vault',
    }]


@mock.patch("lemur.plugins.lemur_gcp.auth.get_gcp_credentials", return_value=token)
@mock.patch("lemur.plugins.lemur_gcp.plugin.certificates.insert_certificate",
            return_value=SUCCESS_INSERT_RESPONSE)
def test_upload(mock_ssl_certificates, mock_credentials):
    plugin = GCPDestinationPlugin()
    assert plugin.upload(
        name,
        body,
        private_key,
        cert_chain,
        options) == SUCCESS_INSERT_RESPONSE

    ssl_certificate_body = {
        "name": certificates.get_name(body),
        "certificate": certificates.full_ca(body, cert_chain),
        "description": "",
        "private_key": private_key,
    }

    # assert our mocks are being called with the params we expect
    mock_ssl_certificates.assert_called_with("lemur-test", ssl_certificate_body, token, "europe-west3")
    mock_credentials.assert_called_with(plugin, options)


cert1 = types.SslCertificate()
cert1.name = "cert1"
cert1.type_ = "SELF_MANAGED"
cert1.certificate = """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""
cert2 = types.SslCertificate()
cert2.name = "cert2"
cert2.type_ = "SELF_MANAGED"
cert2_body = """-----BEGIN CERTIFICATE-----
MIIGyDCCBbCgAwIBAgIQB8uT5tNFO8DHt13XAt08sTANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE
aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMTEwMDYwMDAwMDBa
Fw0yMjEwMDYyMzU5NTlaMGcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhOZXcgWW9y
azERMA8GA1UEBxMITmV3IFlvcmsxFjAUBgNVBAoTDURhdGFkb2csIEluYy4xGjAY
BgNVBAMMESoubG9ncy5kYXRhZDBnLmV1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAr7dV3Kvc4qWtJ2s6j6XqJlxnywoUNG8Vbi7m6yeRtYc2ODwI5r9l
qjgHSLs3jUnSitq30d4a0nk8vOM5j8D2jsq+ZeJc8MWYaOl2fFJQGMqXD549jIP+
0hpoynBVXnUgrJ6k8Rk6gfD3QgGM2oEUqvGu9GRgu4UUm0Wxc6oqcPYwf+kSIRfS
S9Csad3yjMVlJR8JWa0//QOe1aP3qEN/PASH45gc8W0k05K7rfSD/OtYN/XPleWV
8E+4cWaPz647/Wl2dv+IfbfX7cu9YZUZRXl5rbkWatqxRZZbMjELGBTqPprE2oO1
4yE0yQpFSTNMkhjwicSHHtiVYUTq+PwcXwIDAQABo4IDhjCCA4IwHwYDVR0jBBgw
FoAUt2ui6qiqhIx56rTaD5iyxZV2ufQwHQYDVR0OBBYEFFTyapTbg9LBx77F0UzW
fXFbyfa5MC0GA1UdEQQmMCSCESoubG9ncy5kYXRhZDBnLmV1gg9sb2dzLmRhdGFk
MGcuZXUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjCBjwYDVR0fBIGHMIGEMECgPqA8hjpodHRwOi8vY3JsMy5kaWdpY2VydC5j
b20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIwQ0ExLTQuY3JsMECgPqA8hjpodHRw
Oi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIwQ0Ex
LTQuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQICMCkwJwYIKwYBBQUHAgEWG2h0dHA6
Ly93d3cuZGlnaWNlcnQuY29tL0NQUzB/BggrBgEFBQcBAQRzMHEwJAYIKwYBBQUH
MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBJBggrBgEFBQcwAoY9aHR0cDov
L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hBMjU2MjAyMENB
MS0xLmNydDAMBgNVHRMBAf8EAjAAMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkA
dgBGpVXrdfqRIDC1oolp9PN9ESxBdL79SbiFq/L8cP5tRwAAAXxVNJB7AAAEAwBH
MEUCICNG/K9x1KEi+T7k8RtTAFOT2EGTUwvC5vOYqueby7aZAiEAn4pOPELi3xCU
yd/SZiLgvKcjd4VBO1sFfuUaNdr5azoAdgBRo7D1/QF5nFZtuDd4jwykeswbJ8v3
nohCmg3+1IsF5QAAAXxVNJCvAAAEAwBHMEUCIQDntSVU5/s0XbI2YMkJ06MG6lFI
9cVT7llcML6Dfr1vzwIgZv8uenzRN/BHT9xYRYfLZ5iOur4XZ3cPQe5iyeOlzZ0A
dwBByMqx3yJGShDGoToJQodeTjGLGwPr60vHaPCQYpYG9gAAAXxVNJBiAAAEAwBI
MEYCIQD/iAOadnHy+L5amEEkHb+LoDwpvYAphq/vfpMX2+SLJQIhAMlrSbwvZEJk
Feku5r8z5QXpSnggGyDTrFFn8p/2wEPtMA0GCSqGSIb3DQEBCwUAA4IBAQAWa0B8
16iDhZ3ehq1AiE4DssDVq5F+S9350ZRjsIYewV3xSCv53bZzNhuREhLYFFGbRS6u
Ek+J7kgrprMyJDPfDwwAbYxYAl8rn7k8rAAYCKzoKNGRuvraSsgUw1RQ3n+R+adG
HZrPML3L01+KdOz/MO4po1vRlLWMfpWaWjci/zRIy+tJzhHNI+O5gIfrDhyNVX/P
K2Jnoh7x19CEB77QIWylAe+NNzelKHENW/WIOkDYARlcOwdgT8ayOZjma2D+92G3
Li+VZjSVlGpwQJGLikGQ7Kyaub/seL6TYtMQI1irCWvY1GjMawavbNl41/XYFMii
z4bCNWHLrZzQVhbG
-----END CERTIFICATE-----"""
cert2_chain = """-----BEGIN CERTIFICATE-----
MIIEvjCCA6agAwIBAgIQBtjZBNVYQ0b2ii+nVCJ+xDANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0yMTA0MTQwMDAwMDBaFw0zMTA0MTMyMzU5NTlaME8xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxKTAnBgNVBAMTIERpZ2lDZXJ0IFRMUyBS
U0EgU0hBMjU2IDIwMjAgQ0ExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwUuzZUdwvN1PWNvsnO3DZuUfMRNUrUpmRh8sCuxkB+Uu3Ny5CiDt3+PE0J6a
qXodgojlEVbbHp9YwlHnLDQNLtKS4VbL8Xlfs7uHyiUDe5pSQWYQYE9XE0nw6Ddn
g9/n00tnTCJRpt8OmRDtV1F0JuJ9x8piLhMbfyOIJVNvwTRYAIuE//i+p1hJInuW
raKImxW8oHzf6VGo1bDtN+I2tIJLYrVJmuzHZ9bjPvXj1hJeRPG/cUJ9WIQDgLGB
Afr5yjK7tI4nhyfFK3TUqNaX3sNk+crOU6JWvHgXjkkDKa77SU+kFbnO8lwZV21r
eacroicgE7XQPUDTITAHk+qZ9QIDAQABo4IBgjCCAX4wEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQUt2ui6qiqhIx56rTaD5iyxZV2ufQwHwYDVR0jBBgwFoAU
A95QNVbRTLtm8KPiGxvDl7I90VUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGG
GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBABggrBgEFBQcwAoY0aHR0cDovL2Nh
Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNydDBCBgNV
HR8EOzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRH
bG9iYWxSb290Q0EuY3JsMD0GA1UdIAQ2MDQwCwYJYIZIAYb9bAIBMAcGBWeBDAEB
MAgGBmeBDAECATAIBgZngQwBAgIwCAYGZ4EMAQIDMA0GCSqGSIb3DQEBCwUAA4IB
AQCAMs5eC91uWg0Kr+HWhMvAjvqFcO3aXbMM9yt1QP6FCvrzMXi3cEsaiVi6gL3z
ax3pfs8LulicWdSQ0/1s/dCYbbdxglvPbQtaCdB73sRD2Cqk3p5BJl+7j5nL3a7h
qG+fh/50tx8bIKuxT8b1Z11dmzzp/2n3YWzW2fP9NsarA4h20ksudYbj/NhVfSbC
EXffPgK2fPOre3qGNm+499iTcc+G33Mw+nur7SpZyEKEOxEXGlLzyQ4UfaJbcme6
ce1XR2bFuAJKZTRei9AqPCCcUZlM51Ke92sRKw2Sfh3oius2FkOH6ipjv3U/697E
A7sKPPcw7+uvTPyLNhBzPvOk
-----END CERTIFICATE-----"""
cert2.certificate = cert2_body + "\n" + cert2_chain
cert3 = types.SslCertificate()
cert3.name = "cert3"
cert3.type_ = "SELF_MANAGED"
cert3_body = """-----BEGIN CERTIFICATE-----
MIIF+jCCBOKgAwIBAgIRAJqAPlgDCZ0P7t6WamOlz0wwDQYJKoZIhvcNAQELBQAw
gY8xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
BgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDE3MDUGA1UE
AxMuU2VjdGlnbyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBD
QTAeFw0xOTA2MTQwMDAwMDBaFw0yMDA2MjYyMzU5NTlaMFsxITAfBgNVBAsTGERv
bWFpbiBDb250cm9sIFZhbGlkYXRlZDEeMBwGA1UECxMVRXNzZW50aWFsU1NMIFdp
bGRjYXJkMRYwFAYDVQQDDA0qLnN0YWdpbmcuZG9nMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAvQjUjZI4EUBoAHOMnwTAT6ZM6s041Y7b2UqMqTtehPLB
AReHeAoQ4eKZpzU/xpc+BjDibN4fofOmG4ePoMe7oEbDFEBvuQiz6ypwTCaMkTMp
HlNqRP/a6N/tJ9V+Gpony/vnwHy3H77/WWPd5Hi40Ym2l++qkRHWW55tW8Bipk1i
xE9evmz8i2MyJ4k6WqM5nO2MgyI9QQSDGSVhri8HlfrPdsBG1ss0DKFTFSPjzlAK
H9FQrYqLF65VEKbj6DFcXJgoY4d6HK2c/aYFQFD8ZXX99/hCWWtnYRLKZuTYHbuA
LwsbE6cWaWrR6Jt5+v1mJ1tA1dBtZCHJj2723/zKLwIDAQABo4ICgjCCAn4wHwYD
VR0jBBgwFoAUjYxexFStiuF36Zv5mwXhuAGNYeEwHQYDVR0OBBYEFA13nY/TG9la
Q+FbVuUA5OWbucXEMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBJBgNVHSAEQjBAMDQGCysGAQQBsjEB
AgIHMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeB
DAECATCBhAYIKwYBBQUHAQEEeDB2ME8GCCsGAQUFBzAChkNodHRwOi8vY3J0LnNl
Y3RpZ28uY29tL1NlY3RpZ29SU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVy
Q0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAlBgNV
HREEHjAcgg0qLnN0YWdpbmcuZG9nggtzdGFnaW5nLmRvZzCCAQQGCisGAQQB1nkC
BAIEgfUEgfIA8AB3ALvZ37wfinG1k5Qjl6qSe0c4V5UKq1LoGpCWZDaOHtGFAAAB
a1VYtwwAAAQDAEgwRgIhAK3RjYPUPdc/8N93R8IK4G3bOu749Dj+azd3g/TZpYXW
AiEA1MYJDKUveixJ8g9vQ0J8R3h26Zkw+okdXV4VczJ+VL8AdQBep3P531bA57U2
SH3QSeAyepGaDIShEhKEGHWWgXFFWAAAAWtVWLb2AAAEAwBGMEQCIF53/vZJTNAm
nDDslZoOta4w6f87GhP5JKTSwypIVZPtAiAYv9pFkwl+wxF9A4FrpjtVTJEru5R3
HohyvwnBaINOXDANBgkqhkiG9w0BAQsFAAOCAQEAOwG9EAQv8WOra+hTwUVVQelk
2iCtGeV+mC7PAq8hIU+IHvPLFYNX74NEAXCFZUMre5oxXKqL599WNQECGABzaz/6
hb+Bo2A7OkCwbvLuW/70MZn/sHU3Pp2ibg8r1WFHirPNJwzG1OQgKw57jbSBG7Tu
1+QcC36n74JUwfQRkGxp8zOm3irFQnnWBHYU1tvHX7QYlLW/LMpSlSEDDty4j9/V
BQRXuZ5ZZxT2fkCSFswAy/c7zkcpLtYgc5BvCzAEXYVDMB2CKbjvIYAwPhfOpOxg
6t0kj+z+O3my1n6017BXy0v9kErIPL/mcD2KcRl+CeZ9DUxNdvxlIx/YfCfxqw==
-----END CERTIFICATE-----"""
cert3_chain = """-----BEGIN CERTIFICATE REQUEST-----
MIIChjCCAW4CAQAwGDEWMBQGA1UEAwwNKi5zdGFnaW5nLmRvZzCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAL0I1I2SOBFAaABzjJ8EwE+mTOrNONWO29lK
jKk7XoTywQEXh3gKEOHimac1P8aXPgYw4mzeH6HzphuHj6DHu6BGwxRAb7kIs+sq
cEwmjJEzKR5TakT/2ujf7SfVfhqaJ8v758B8tx++/1lj3eR4uNGJtpfvqpER1lue
bVvAYqZNYsRPXr5s/ItjMieJOlqjOZztjIMiPUEEgxklYa4vB5X6z3bARtbLNAyh
UxUj485QCh/RUK2KixeuVRCm4+gxXFyYKGOHehytnP2mBUBQ/GV1/ff4QllrZ2ES
ymbk2B27gC8LGxOnFmlq0eibefr9ZidbQNXQbWQhyY9u9t/8yi8CAwEAAaApMCcG
CSqGSIb3DQEJDjEaMBgwFgYDVR0RBA8wDYILc3RhZ2luZy5kb2cwDQYJKoZIhvcN
AQELBQADggEBABmGbX2IMpeJiJCip/8TWceLtPxt/vMoTbX0Suz3lh9SBViMhdA5
swG3nbGUaDWfYFxj13BUmHbg4Pz2J7xgUfcWADs2tibllxfHldUmz8OcP3og+F8j
WgLwi3/o+fVIftfUp1yZCvEXJQmWKImm3miuDauRIq328nOLTc9vQ1GLqt8KtWqG
Bjs8HPMyGoWDnINfZgH/Fap8ox2jenFoP27RDAaJ6hS4FtpCB7897yUq/ZE+tz0F
sl+4yFgI6dR4BT8bs2VPAst4o3LSOh0S1yWBqGuwRDy/05Wc98elF4OdTCkm2sg4
Gv/AtMedZ3VQr3PbxbZ2ZzF4V52LFTWKL3I=
-----END CERTIFICATE REQUEST-----"""
cert3.certificate = cert3_body + "\n" + cert3_chain
cert4 = types.SslCertificate()
cert4.name = "cert4"
cert4.type_ = "MANAGED"


@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPSourcePlugin.get_option")
@mock.patch("lemur.plugins.lemur_gcp.auth.get_gcp_credentials", return_value=token)
@mock.patch("google.cloud.compute_v1.services.ssl_certificates.SslCertificatesClient.list")
def test_get_certificates(mock_ssl_client_list, mock_credentials, mock_get_option):
    from lemur.plugins.lemur_gcp.plugin import GCPSourcePlugin
    mock_ssl_client_list.return_value = [cert1, cert2, cert3, cert4]
    mock_get_option.side_effect = ["lemur-test", None]
    certs = GCPSourcePlugin().get_certificates(options)
    assert len(certs) == 3
    assert certs[0] == {
        "body": cert1.certificate,
        "chain": "",
        "name": "cert1",
    }
    assert certs[1] == {
        "body": cert2_body,
        "chain": cert2_chain,
        "name": "cert2",
    }
    assert certs[2] == {
        "body": cert3_body,
        "chain": "",
        "name": "cert3",
    }
    mock_ssl_client_list.assert_called_once_with(project="lemur-test")


@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPSourcePlugin.get_option")
@mock.patch("lemur.plugins.lemur_gcp.auth.get_gcp_credentials", return_value=token)
@mock.patch("google.cloud.compute_v1.services.region_ssl_certificates.RegionSslCertificatesClient.list")
def test_get_regional_certificates(mock_ssl_client_list, mock_credentials, mock_get_option):
    from lemur.plugins.lemur_gcp.plugin import GCPSourcePlugin
    mock_ssl_client_list.return_value = [cert1, cert2, cert3, cert4]
    mock_get_option.side_effect = ["lemur-test", "europe-west3"]
    certs = GCPSourcePlugin().get_certificates(options)
    assert len(certs) == 3
    assert certs[0] == {
        "body": cert1.certificate,
        "chain": "",
        "name": "cert1",
    }
    assert certs[1] == {
        "body": cert2_body,
        "chain": cert2_chain,
        "name": "cert2",
    }
    assert certs[2] == {
        "body": cert3_body,
        "chain": "",
        "name": "cert3",
    }
    mock_ssl_client_list.assert_called_once_with(project="lemur-test", region="europe-west3")


@mock.patch("lemur.plugins.lemur_gcp.auth.get_gcp_credentials_from_vault",
            return_value="ya29.c.b0AXv0zTN36HtXN2cJolg9tAj0vGAOT29FF-WNxQzvPu")
def test_get_gcp_credentials(mock_get_gcp_credentials_from_vault):
    plugin = GCPDestinationPlugin()
    assert get_gcp_credentials(plugin, options) == token

    mock_get_gcp_credentials_from_vault.assert_called_with(plugin, options)
