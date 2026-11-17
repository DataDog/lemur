import os

_basedir = os.path.abspath(os.path.dirname(__file__))

# Enable only in sandbox; all its COA paths must use the isolated test prefix.
# Keep disabled in commercial and government.
SANDBOX_COA_PATH_ISOLATION = False
