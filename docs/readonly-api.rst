Read-only metadata API
======================

The optional ``/api/1/readonly`` API accepts short-lived JWTs from explicitly
configured issuers. It is disabled by default. Enable it only on the intended
instance, with all of the following settings:

.. code-block:: python

    READ_ONLY_API_ENABLED = True
    READ_ONLY_API_AUDIENCE = "your-namespace"
    READ_ONLY_API_ISSUERS = ["https://your-issuer.example/identity"]
    READ_ONLY_API_ENVIRONMENT = "test"

Tokens must have a verified signature, matching issuer and audience, unexpired
``exp``, nonempty ``sub`` and ``email``, and an ``environment`` claim matching the
configuration. The email must identify an existing active Lemur user. This API
does not create users, change roles, exchange credentials, or issue Lemur tokens.
Its credentials are not accepted by the normal Lemur management API.

The only supported operations are GET requests to ``readonly/session``,
``readonly/certificates`` and ``readonly/certificates/<numeric-id>``. The list
accepts ``page``, ``count`` (up to 100), and a common-name ``query``. Responses
project an explicit set of metadata, excluding private keys, PEM material,
certificate requests, destination options and source configuration.

All other methods are rejected, regardless of the authenticated user's roles.
Each request uses a separate PostgreSQL read-only transaction as an additional
enforcement boundary. Other database engines are not supported by this API.
