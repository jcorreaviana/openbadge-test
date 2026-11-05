import json
import re

import jwt as pyjwt
import pytest
from openbadgeslib.ob3 import OB3VerificationError

from src import export, hosting, keystore
from src.demo import tamper_jwt_payload
from src.inspect import decode
from src.issue import RECIPIENT_ID, build_achievements
from src.keys import ephemeral_jwt_key

BASE_URL = "https://example.com/openbadge-test"
PUBLIC_RSA_MEMBERS = {"kty", "n", "e", "alg", "use", "kid"}
PRIVATE_MARKER = re.compile("-----BEGIN [A-Z ]*" + "PRIVATE KEY-----")


@pytest.fixture(autouse=True)
def temp_keydir(tmp_path, monkeypatch):
    """Nenhum teste toca no keystore real em ~/.openbadge-test."""
    monkeypatch.setenv(keystore.ENV_VAR, str(tmp_path / "keys"))
    monkeypatch.delenv(hosting.BASE_URL_ENV, raising=False)


@pytest.fixture
def site():
    return hosting.Site(BASE_URL)


@pytest.fixture
def docs(tmp_path, site):
    directory = tmp_path / "docs"
    hosting.write_site(site, keystore.load_or_create("rsa").public_pem, directory)
    return directory


@pytest.fixture
def token(site, docs):
    return hosting.issue_hosted(site, keystore.load_or_create("rsa").private_pem,
                                build_achievements()[0])


def _other_rsa_public_pem():
    return ephemeral_jwt_key("RS256").public_pem


def _rewrite(path, content):
    path.write_text(json.dumps(content, indent=2) + "\n")


# ── docs/ versionado: só chave pública ───────────────────────────────────────

def _committed_docs():
    files = sorted(p for p in hosting.DOCS_DIR.rglob("*") if p.is_file())
    if not files:
        pytest.skip("docs/ ainda não foi gerado")
    return files


def test_committed_docs_have_no_private_fields():
    for path in _committed_docs():
        text = path.read_text(encoding="utf-8")
        assert not PRIVATE_MARKER.search(text), path
        if path.suffix == ".json":
            assert hosting.find_private_members(json.loads(text)) == [], path


def test_committed_docs_jwks_only_public_rsa_members():
    jwks = json.loads((hosting.DOCS_DIR / hosting.JWKS_FILE).read_text())
    jwk = json.loads((hosting.DOCS_DIR / hosting.JWK_FILE).read_text())
    for key in [*jwks["keys"], jwk]:
        assert key["kty"] == "RSA"
        assert set(key) <= PUBLIC_RSA_MEMBERS


def test_committed_docs_are_consistent():
    _committed_docs()
    site = hosting.Site(hosting.DEFAULT_BASE_URL)
    read = lambda name: json.loads((hosting.DOCS_DIR / name).read_text())  # noqa: E731
    jwk, jwks, did_doc = read(hosting.JWK_FILE), read(hosting.JWKS_FILE), read(hosting.DID_FILE)
    profile = read(hosting.PROFILE_FILE)

    assert profile["id"] == site.profile_url and "Profile" in profile["type"]
    assert jwk["kid"] == site.key_url
    assert jwks["keys"] == [jwk]
    assert did_doc["id"] == site.did == "did:web:jcorreaviana.github.io:openbadge-test"
    published = did_doc["verificationMethod"][0]["publicKeyJwk"]
    assert (published["n"], published["e"]) == (jwk["n"], jwk["e"])


def test_generated_site_has_no_private_fields(docs):
    for path in docs.iterdir():
        text = path.read_text()
        assert not PRIVATE_MARKER.search(text)
        assert hosting.find_private_members(json.loads(text)) == []


def test_find_private_members_detects_nested():
    leaked = {"keys": [{"kty": "RSA", "n": "x", "e": "AQAB", "d": "segredo"}]}
    assert hosting.find_private_members(leaked) == ["$.keys[0].d"]


def test_site_refuses_non_rsa_key():
    with pytest.raises(ValueError, match="RSA"):
        hosting.public_jwk(ephemeral_jwt_key("ES256").public_pem)


# ── URL base ─────────────────────────────────────────────────────────────────

def test_base_url_priority(monkeypatch):
    assert hosting.site_from().base_url == hosting.DEFAULT_BASE_URL
    monkeypatch.setenv(hosting.BASE_URL_ENV, "https://env.example/x/")
    assert hosting.site_from().base_url == "https://env.example/x"
    assert hosting.site_from(BASE_URL).base_url == BASE_URL


@pytest.mark.parametrize("url", ["http://example.com/x", "example.com/x",
                                 "https://user:pw@example.com/x"])
def test_base_url_rejects_unsafe(url):
    with pytest.raises(ValueError):
        hosting.site_from(url)


# ── verificação a partir dos arquivos publicados ─────────────────────────────

def test_hosted_token_uses_kid_not_jwk(token, site):
    header, payload, _ = decode(token)
    assert header == {"alg": "RS256", "kid": site.key_url, "typ": "JWT"}
    assert payload["iss"] == payload["issuer"]["id"] == site.profile_url


def test_verify_from_published_files(token, site, docs):
    credential = hosting.verify_hosted(token, site, RECIPIENT_ID, docs)
    assert credential.issuer.id == site.profile_url


def test_verify_from_published_files_without_keystore(token, site, docs, monkeypatch):
    def forbidden(*_):
        raise AssertionError("verify_hosted não pode ler o keystore")
    monkeypatch.setattr(keystore, "load_or_create", forbidden)
    hosting.verify_hosted(token, site, RECIPIENT_ID, docs)


def test_hosted_tampered_rejected(token, site, docs):
    with pytest.raises(OB3VerificationError):
        hosting.verify_hosted(tamper_jwt_payload(token, "Doutorado"), site,
                              RECIPIENT_ID, docs)


def test_hosted_signed_by_attacker_with_same_kid_rejected(site, docs):
    attacker = ephemeral_jwt_key("RS256")
    forged = hosting.issue_hosted(site, attacker.private_pem, build_achievements()[0])
    with pytest.raises(OB3VerificationError, match="(?i)signature"):
        hosting.verify_hosted(forged, site, RECIPIENT_ID, docs)


def test_hosted_wrong_recipient_rejected(token, site, docs):
    with pytest.raises(OB3VerificationError):
        hosting.verify_hosted(token, site, "mailto:outra@example.com", docs)


def test_jwks_not_matching_token_key_rejected(token, site, docs):
    other = hosting.public_jwk(_other_rsa_public_pem())
    _rewrite(docs / hosting.JWKS_FILE, {"keys": [{**other, "kid": site.key_url}]})
    with pytest.raises(OB3VerificationError, match="JWKS"):
        hosting.verify_hosted(token, site, RECIPIENT_ID, docs)


def test_published_jwk_not_matching_token_key_rejected(token, site, docs):
    # Site inteiro regenerado com outra chave: tudo consistente entre si, mas a
    # assinatura do token não bate.
    hosting.write_site(site, _other_rsa_public_pem(), docs)
    with pytest.raises(OB3VerificationError, match="(?i)signature"):
        hosting.verify_hosted(token, site, RECIPIENT_ID, docs)


def test_did_document_not_matching_rejected(token, site, docs):
    other = hosting.build_site_files(site, _other_rsa_public_pem())
    _rewrite(docs / hosting.DID_FILE, other[hosting.DID_FILE])
    with pytest.raises(OB3VerificationError, match="did.json"):
        hosting.verify_hosted(token, site, RECIPIENT_ID, docs)


def test_profile_with_other_id_rejected(token, site, docs):
    profile = json.loads((docs / hosting.PROFILE_FILE).read_text())
    _rewrite(docs / hosting.PROFILE_FILE, {**profile, "id": "https://example.com/outro"})
    with pytest.raises(OB3VerificationError, match="perfil"):
        hosting.verify_hosted(token, site, RECIPIENT_ID, docs)


def test_published_jwk_with_private_field_rejected(token, site, docs):
    jwk = json.loads((docs / hosting.JWK_FILE).read_text())
    _rewrite(docs / hosting.JWK_FILE, {**jwk, "d": "AAAA"})
    with pytest.raises(OB3VerificationError, match="privados"):
        hosting.verify_hosted(token, site, RECIPIENT_ID, docs)


@pytest.mark.parametrize("kid", [
    "https://evil.example/issuer-key.json",
    f"{BASE_URL}/../issuer-key.json",
    f"{BASE_URL}/issuer-key.json?x=1",
    f"{BASE_URL}/",
])
def test_kid_outside_published_site_rejected(site, docs, kid):
    signer = hosting.KidSigner(keystore.load_or_create("rsa").private_pem, kid=kid)
    forged = signer.sign_payload(pyjwt.decode(
        hosting.issue_hosted(site, keystore.load_or_create("rsa").private_pem,
                             build_achievements()[0]),
        options={"verify_signature": False}))
    with pytest.raises(OB3VerificationError):
        hosting.verify_hosted(forged, site, RECIPIENT_ID, docs)


def test_token_without_kid_rejected(site, docs):
    plain = hosting.OB3Signer(keystore.load_or_create("rsa").private_pem).sign_payload(
        {"iss": site.profile_url})
    with pytest.raises(OB3VerificationError, match="kid"):
        hosting.verify_hosted(plain, site, RECIPIENT_ID, docs)


# ── export ───────────────────────────────────────────────────────────────────

def test_export_hosted(tmp_path, monkeypatch, docs, capsys):
    monkeypatch.setattr(export, "OUT_DIR", tmp_path / "out")
    assert export.main(["--alg", "RS256", "--hosted", "--base-url", BASE_URL,
                        "--docs-dir", str(docs)]) == 0
    raw = (tmp_path / "out" / "badge_rs256_hosted.jwt").read_text()
    assert raw == raw.strip()  # sem "\n" final
    header, payload, _ = decode(raw)
    assert "jwk" not in header and header["kid"] == f"{BASE_URL}/{hosting.JWK_FILE}"
    assert payload["issuer"]["id"] == f"{BASE_URL}/{hosting.PROFILE_FILE}"
    assert "verificado a partir de" in capsys.readouterr().out


def test_export_hosted_fails_with_stale_docs(tmp_path, monkeypatch, site, capsys):
    stale = tmp_path / "stale"
    hosting.write_site(site, _other_rsa_public_pem(), stale)
    monkeypatch.setattr(export, "OUT_DIR", tmp_path / "out")
    assert export.main(["--hosted", "--base-url", BASE_URL,
                        "--docs-dir", str(stale)]) == 1
    assert "src.hosting" in capsys.readouterr().err


def test_export_hosted_requires_rs256():
    with pytest.raises(SystemExit):
        export.main(["--alg", "ES256", "--hosted"])


@pytest.mark.parametrize("alg", ["RS256", "ES256", "EdDSA"])
def test_exported_token_has_no_trailing_newline(tmp_path, monkeypatch, alg):
    # Um "\n" final vira parte da assinatura para quem não faz strip.
    monkeypatch.setattr(export, "OUT_DIR", tmp_path / "out")
    assert export.main(["--alg", alg]) == 0
    raw = (tmp_path / "out" / f"badge_{alg.lower()}.jwt").read_text()
    assert raw == raw.strip()
