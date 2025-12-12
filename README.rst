Lemur
=====

#Releases
See docs/doing-a-release.rst

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

Lemur runs on Python 3.9.
We deploy on Ubuntu and develop mostly on OS X.


Project resources
=================

- `Lemur Blog Post <http://techblog.netflix.com/2015/09/introducing-lemur.html>`_
- `Documentation <http://lemur.readthedocs.io/>`_
- `Source code <https://github.com/netflix/lemur>`_
- `Issue tracker <https://github.com/netflix/lemur/issues>`_
- `Docker <https://github.com/Netflix/lemur-docker>`_


Local Development and Testing
==============================

Prerequisites
-------------

- Python 3.9
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

Set the database connection string and run tests::

    export SQLALCHEMY_DATABASE_URI=postgresql://lemur:lemur@localhost:5432/lemur
    pytest lemur/tests/test_sources.py -v

Run the full test suite::

    export SQLALCHEMY_DATABASE_URI=postgresql://lemur:lemur@localhost:5432/lemur
    make test-python
