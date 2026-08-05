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

# Days before expiry used when seeding the default RotationPolicy row (lemur create_config)
# and as the fallback window for certs with no rotation_policy_id (see certificates/models.py).
LEMUR_DEFAULT_ROTATION_INTERVAL = 30
