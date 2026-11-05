import os
import re
import shutil
import stat
import subprocess

import pytest
from openbadgeslib.ob3 import OB3Signer, OB3VerificationError

from src import export, keystore
from src.demo import tamper_jwt_payload
from src.inspect import decode, key_reference
from src.issue import RECIPIENT_ID, build_credential, issue_all
from src.keys import HTTP_ISSUER_ID, ephemeral_jwt_key, generate_keys
from src.verify import verify_jwt


@pytest.fixture(autouse=True)
def temp_keydir(tmp_path, monkeypatch):
    """Nenhum teste toca no keystore real em ~/.openbadge-test."""
    directory = tmp_path / "keys"
    monkeypatch.setenv(keystore.ENV_VAR, str(directory))
    return directory


@pytest.fixture
def issued_rs256():
    return issue_all(generate_keys(), "RS256")


# ── RS256 / ES256 ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_round_trip(alg):
    issued = issue_all(generate_keys(), alg)
    for token in issued.jwts:
        header, _, _ = decode(token)
        assert header["alg"] == alg
        credential = verify_jwt(token, issued.jwt_key.public_pem, RECIPIENT_ID)
        assert credential.issuer.id == issued.jwt_key.issuer_id


def test_rs256_issuer_is_https_url(issued_rs256):
    # did:key não aceita RSA, então o emissor RS256 é identificado por URL.
    assert issued_rs256.jwt_key.issuer_id == HTTP_ISSUER_ID


def test_rs256_tampered_token_rejected(issued_rs256):
    forged = tamper_jwt_payload(issued_rs256.jwts[0], "Doutorado")
    with pytest.raises(OB3VerificationError):
        verify_jwt(forged, issued_rs256.jwt_key.public_pem, RECIPIENT_ID)


def test_rs256_verified_with_other_issuer_key_rejected(issued_rs256):
    other = ephemeral_jwt_key("RS256")
    with pytest.raises(OB3VerificationError):
        verify_jwt(issued_rs256.jwts[0], other.public_pem, RECIPIENT_ID)


def test_rs256_signed_by_other_issuer_rejected(issued_rs256):
    # O atacante embute a própria chave no "jwk" do cabeçalho; o verificador
    # precisa ignorá-la e usar a chave fixada do emissor.
    attacker = ephemeral_jwt_key("RS256")
    forged = OB3Signer(attacker.private_pem, algorithm="RS256").sign(
        build_credential(issued_rs256.jwt_issuer, issued_rs256.achievements[0]))
    with pytest.raises(OB3VerificationError):
        verify_jwt(forged, issued_rs256.jwt_key.public_pem, RECIPIENT_ID)


# ── keystore ─────────────────────────────────────────────────────────────────

def test_keystore_reuses_same_pair(temp_keydir):
    first = keystore.load_or_create("rsa")
    second = keystore.load_or_create("rsa")
    assert first.private_pem == second.private_pem
    assert first.public_pem == second.public_pem
    assert first.private_path.parent == temp_keydir.resolve()


def test_keystore_permissions(temp_keydir):
    stored = keystore.load_or_create("rsa")
    assert stat.S_IMODE(temp_keydir.stat().st_mode) == 0o700
    assert stat.S_IMODE(stored.private_path.stat().st_mode) == 0o600


def test_keystore_refuses_loose_permissions():
    stored = keystore.load_or_create("rsa")
    os.chmod(stored.private_path, 0o644)
    with pytest.raises(keystore.KeystoreError, match="chmod 600"):
        keystore.load_or_create("rsa")


def test_keystore_refuses_dir_inside_repo(monkeypatch):
    inside = keystore.PROJECT_ROOT / "out" / "keys-teste"
    monkeypatch.setenv(keystore.ENV_VAR, str(inside))
    with pytest.raises(keystore.KeystoreError, match="dentro do repositório"):
        keystore.load_or_create("rsa")
    assert not inside.exists()


def test_keystore_repr_hides_private_key():
    assert b"PRIVATE" not in repr(keystore.load_or_create("rsa")).encode()


def test_default_keydir_is_outside_repo(monkeypatch):
    monkeypatch.delenv(keystore.ENV_VAR)
    assert keystore.PROJECT_ROOT not in keystore.key_dir().parents


# ── nada de chave no repositório ─────────────────────────────────────────────

def test_no_key_files_tracked_by_git():
    if shutil.which("git") is None:
        pytest.skip("git não disponível")
    result = subprocess.run(["git", "ls-files", "-z"], cwd=keystore.PROJECT_ROOT,
                            capture_output=True, check=False)
    if result.returncode != 0:
        pytest.skip("não é um repositório git")
    files = [f for f in result.stdout.decode().split("\0") if f]
    assert files, "git ls-files vazio"

    bad_names = [f for f in files
                 if re.search(r"\.(pem|key|p12|pfx|jwk)$|(^|/)keys/|(^|/)\.env", f)]
    assert bad_names == []

    # Padrão montado por partes para não casar com este próprio arquivo.
    private_marker = re.compile(("-----BEGIN [A-Z ]*" + "PRIVATE KEY-----").encode())
    with_private_key = [f for f in files
                        if private_marker.search((keystore.PROJECT_ROOT / f).read_bytes())]
    assert with_private_key == []


# ── export e inspect ─────────────────────────────────────────────────────────

def test_export_and_inspect(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(export, "OUT_DIR", tmp_path / "out")
    assert export.main(["--alg", "RS256"]) == 0
    token = (tmp_path / "out" / "badge_rs256.jwt").read_text()
    header, payload, sig_len = decode(token)
    assert header["alg"] == "RS256" and header["jwk"]["kty"] == "RSA"
    assert "d" not in header["jwk"]  # só parâmetros públicos
    assert key_reference(header) == "jwk"
    assert payload["iss"] == HTTP_ISSUER_ID and sig_len == 256
    assert "verificado localmente" in capsys.readouterr().out
