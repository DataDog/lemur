# This is just Python which means you can inherit and tweak settings

import os

_basedir = os.path.abspath(os.path.dirname(__file__))

THREADS_PER_PAGE = 8

# General

# These will need to be set to `True` if you are developing locally
CORS = False
DEBUG = False

# Default rotation policy: days before expiry a cert is eligible for rotation.
# Certs created without an explicit rotation_policy fall back to the named
# "default" policy, which is kept in sync with this value.
LEMUR_DEFAULT_ROTATION_INTERVAL = 60

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"
