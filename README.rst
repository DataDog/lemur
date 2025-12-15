Lemur
=====

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/Netflix/lemur
   :target: https://gitter.im/Netflix/lemur?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://readthedocs.org/projects/lemur/badge/?version=latest
    :target: https://lemur.readthedocs.io
    :alt: Latest Docs

.. image:: https://img.shields.io/badge/NetflixOSS-active-brightgreen.svg

.. image:: https://coveralls.io/repos/github/Netflix/lemur/badge.svg?branch=master
    :target: https://coveralls.io/github/Netflix/lemur?branch=master



Lemur manages TLS certificate creation. While not able to issue certificates itself, Lemur acts as a broker between CAs
and environments providing a central portal for developers to issue TLS certificates with 'sane' defaults.

Lemur runs on Python 3.10.
We deploy on Ubuntu and develop mostly on OS X.


Project resources
=================

- `Lemur Blog Post <http://techblog.netflix.com/2015/09/introducing-lemur.html>`_
- `Documentation <http://lemur.readthedocs.io/>`_
- `Source code <https://github.com/netflix/lemur>`_
- `Issue tracker <https://github.com/netflix/lemur/issues>`_
- `Docker <https://github.com/Netflix/lemur-docker>`_


Docker Environments
===================

This repository contains multiple Dockerfiles for different purposes:

``Dockerfile`` (root directory)
    **Testing environment** - Minimal build based on ``ubuntu:22.04`` with Python 3.10 and Node.js 18 for running tests.
    Used by ``docker-compose.yml`` to run the test suite.

    Usage: ``docker compose up test``

``docker/Dockerfile``
    **Local development environment** - Full-featured development setup based on ``ubuntu:22.04``
    with Python 3.10 and Node.js 18, including nginx, supervisor, and celery workers.
    Provides a complete Lemur stack for local development. Used by ``docker/docker-compose.yml``.

    Usage: ``cd docker && docker compose up``

    Access at ``http://localhost:8087`` (HTTP) and ``https://localhost:8447`` (HTTPS)

``publish/Dockerfile``
    **Production and staging images** - Multi-stage build using DataDog's GBI Ubuntu 22.04 base image
    (Python 3.10). Used by GitLab CI to build both regular and FIPS-compliant images for deployment.

    Controlled by ``.gitlab-ci.yml`` via ``.campaigns/build_and_push_image.sh``


Local Development and Testing
==============================

Prerequisites
-------------

- Python 3.10
- Node.js and npm (for frontend build)
- Docker (for PostgreSQL database)

Setup
-----

1. Create and activate a virtual environment::

    python3 -m venv venv
    source venv/bin/activate

2. Start PostgreSQL database::

    docker compose up -d postgres

3. Install dependencies and build frontend::

    make develop

   This command will install npm dependencies, Python dependencies in development mode, and build frontend assets with gulp.

Running Tests
-------------

**With Docker:**

.. code-block:: bash

    docker compose up test

**Without Docker:**

Set the database connection string and run tests::

    export SQLALCHEMY_DATABASE_URI=postgresql://lemur:lemur@localhost:5432/lemur
    pytest lemur/tests/test_sources.py -v

Run the full test suite::

    export SQLALCHEMY_DATABASE_URI=postgresql://lemur:lemur@localhost:5432/lemur
    make test            # Run linting and tests
    make test-python     # Run Python tests only
