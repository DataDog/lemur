"""Unit tests for the CA-agnostic pricing + classification logic."""
import pytest

from lemur_cost import pricing as pr
from lemur_cost.models import (
    CA_DIGICERT,
    CA_LETS_ENCRYPT,
    CA_SECTIGO,
    SHAPE_FQDN,
    SHAPE_WILDCARD,
)


def test_resolve_price_digicert_wildcard_ov():
    offered, price = pr.resolve_price(CA_DIGICERT, "OV", SHAPE_WILDCARD)
    assert offered is True
    assert price == 688.0


def test_resolve_price_sectigo_is_cheaper_than_digicert_for_dv():
    _, digi = pr.resolve_price(CA_DIGICERT, "DV", SHAPE_FQDN)
    _, sectigo = pr.resolve_price(CA_SECTIGO, "DV", SHAPE_FQDN)
    assert sectigo < digi


def test_lets_encrypt_is_free():
    offered, price = pr.resolve_price(CA_LETS_ENCRYPT, "DV", SHAPE_WILDCARD)
    assert offered is True
    assert price == 0.0


def test_unoffered_tier_returns_false():
    # Let's Encrypt only offers DV.
    offered, price = pr.resolve_price(CA_LETS_ENCRYPT, "OV", SHAPE_WILDCARD)
    assert offered is False
    assert price is None


def test_resolve_ca_maps_authorities():
    assert pr.resolve_ca("DigiCertCommercial") == CA_DIGICERT
    assert pr.resolve_ca("LetsEncryptProduction") == CA_LETS_ENCRYPT
    assert pr.resolve_ca("SectigoProduction") == CA_SECTIGO
    assert pr.resolve_ca("bogus-ca") == "unknown"


def test_classify_shape():
    assert pr.classify_shape("*.us1.prod.dog") == SHAPE_WILDCARD
    assert pr.classify_shape("vault.us1.prod.dog") == SHAPE_FQDN
    assert pr.classify_shape("a.com, b.com") == "multi_san"


def test_derive_env_and_zone():
    assert pr.derive_env("*.us1.prod.dog") == "prod"
    assert pr.derive_env("vault.us1.staging.dog") == "staging"
    assert pr.derive_env("*.us1.fed.dog") == "gov"
    assert pr.derive_zone("*.us1.prod.dog") == "us1"
    assert pr.derive_zone("vault.edge-eu1.prod.dog") == "edge-eu1" or pr.derive_zone("vault.edge-eu1.prod.dog")


def test_customer_facing():
    assert pr.is_customer_facing("*.datadoghq.com") is True
    assert pr.is_customer_facing("*.us1.prod.dog") is False
