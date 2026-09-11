# This is just Python which means you can inherit and tweak settings

import os

_basedir = os.path.abspath(os.path.dirname(__file__))

THREADS_PER_PAGE = 8

# General

# These will need to be set to `True` if you are developing locally
CORS = False
DEBUG = False

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"

# Persistent DNS TXT (DNS-PERSIST-01) DCV: expected account URIs, one per CA.
# These are account-level (the same value for every domain under that CA).
# Override per deployment (e.g. in the k8s chart lemur.conf.py) if a deployment
# uses a different CA account. Used by emit_persist_record_metrics to verify
# _validation-persist.<domain> records.
DCV_PERSIST_ACCOUNT_URIS = {
    "digicert.com": "https://digicert.com/account/e4121f47236aff78d0402aa9459d446a2dcdbf6fd09d65b0b4cb6d2295ed13b2",
    "sectigo.com": "acct:13166504716@sectigo.com",
}
