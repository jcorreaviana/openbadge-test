import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

import pytest
from openbadgeslib.ob3 import OB3VerificationError

from src import keystore, visual
from src.baked import bake, build_visual_credential, verify_baked
from src.experiment import (credential_element, tamper_drawing, tamper_token,
                            transplant)
from src.images import ACHIEVEMENT_ART, ISSUER_LOGO, decode_svg_data_uri
from src.issue import RECIPIENT_EMAIL
from src.keys import ephemeral_jwt_key

SVG_NS = "{http://www.w3.org/2000/svg}"
OB3_NS = "https://purl.imsglobal.org/ob/v3p0"


@pytest.fixture(autouse=True)
def temp_keydir(tmp_path, monkeypatch):
    monkeypatch.setenv(keystore.ENV_VAR, str(tmp_path / "keys"))


@pytest.fixture(scope="module")
def key():
    return ephemeral_jwt_key("RS256")


@pytest.fixture(scope="module")
def baked(key):
    return bake(key, build_visual_credential(key))


# ── artes ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [ISSUER_LOGO, ACHIEVEMENT_ART])
def test_assets_are_simple_self_contained_svgs(path):
    root = ET.parse(path).getroot()
    assert root.tag == f"{SVG_NS}svg"
    assert (root.get("width"), root.get("height"), root.get("viewBox")) == \
        ("512", "512", "0 0 512 512")
    text = path.read_text()
    for forbidden in ("href", "<image", "url(", "@import", "@font-face", "<script"):
        assert forbidden not in text, forbidden


# ── badge baked ──────────────────────────────────────────────────────────────

def test_baked_round_trip(key, baked):
    credential = verify_baked(baked, key.public_pem)
    assert credential.achievement.name == "Python Básico"
    assert credential.issuer.id == key.issuer_id
    # As imagens assinadas na credencial são as artes de assets/.
    assert decode_svg_data_uri(credential.achievement.image_url) == ACHIEVEMENT_ART.read_bytes()
    assert decode_svg_data_uri(credential.issuer.image_url) == ISSUER_LOGO.read_bytes()


def test_baked_svg_is_well_formed(baked):
    root = ET.fromstring(baked)
    assert root.tag == f"{SVG_NS}svg" and root.get("width") == "512"
    carriers = [el for el in root if el.tag == f"{{{OB3_NS}}}credential"]
    assert len(carriers) == 1 and carriers[0].get("verify", "").count(".") == 2
    # O desenho original continua lá.
    assert len([el for el in root if el.tag == f"{SVG_NS}text"]) == 3


def test_tampered_token_inside_svg_rejected(key, baked):
    with pytest.raises(OB3VerificationError):
        verify_baked(tamper_token(baked), key.public_pem)


def test_forged_badge_rejected(key, baked):
    with pytest.raises(OB3VerificationError):
        verify_baked(visual.make_tampered(baked), key.public_pem)


def test_baked_with_other_issuer_key_rejected(baked):
    with pytest.raises(OB3VerificationError):
        verify_baked(baked, ephemeral_jwt_key("RS256").public_pem)


def test_svg_without_credential_rejected(key):
    with pytest.raises(OB3VerificationError):
        verify_baked(ACHIEVEMENT_ART.read_bytes(), key.public_pem)


# ── experimento da etapa 4 ───────────────────────────────────────────────────

def test_drawing_is_not_covered_by_signature(key, baked):
    """Comportamento OBSERVADO com openbadgeslib 4.6.3: alterar o desenho, ou
    mover a credencial para outro SVG, não invalida a verificação. Se este
    teste falhar, a biblioteca mudou e a seção "Aparência do badge" do README
    precisa ser revista."""
    redrawn = tamper_drawing(baked)
    assert redrawn != baked
    assert credential_element(redrawn) == credential_element(baked)
    assert b"Doutorado" in redrawn

    for altered in (redrawn, transplant(baked, ISSUER_LOGO.read_bytes())):
        credential = verify_baked(altered, key.public_pem)
        # Passa, e os dados assinados continuam sendo os originais.
        assert credential.achievement.name == "Python Básico"
        assert decode_svg_data_uri(credential.achievement.image_url) == ACHIEVEMENT_ART.read_bytes()


# ── preview ──────────────────────────────────────────────────────────────────

class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[str] = []
        self.img_src: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "img":
            self.img_src.append(dict(attrs)["src"])


@pytest.fixture
def preview(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(visual, "OUT_DIR", tmp_path / "out")
    assert visual.main([]) == 0
    capsys.readouterr()
    return (tmp_path / "out")


def test_visual_writes_both_files(preview):
    assert (preview / "badge_baked.svg").is_file()
    assert (preview / "preview.html").is_file()
    ET.fromstring((preview / "badge_baked.svg").read_bytes())


def test_preview_has_expected_fields(preview):
    html = (preview / "preview.html").read_text(encoding="utf-8")
    for expected in ("verificado", "adulterado: rejeitado", "Python Básico",
                     "Fundamentos de programação em Python.",
                     "Concluiu os exercícios e o projeto final.",
                     RECIPIENT_EMAIL, "Escola Exemplo", "Verificado em",
                     "Invalid signature", visual.FORGED_NAME):
        assert expected in html, expected
    assert re.search(r"Verificado em \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", html)


def test_preview_is_self_contained(preview):
    html = (preview / "preview.html").read_text(encoding="utf-8")
    parser = _Collector()
    parser.feed(html)
    assert "script" not in parser.tags
    assert "link" not in parser.tags
    # Desenho da conquista e logo nos dois cartões, todos embutidos.
    assert len(parser.img_src) == 4
    assert all(src.startswith("data:image/svg+xml;base64,") for src in parser.img_src)
    assert "default-src 'none'" in html


def test_verified_card_shows_signed_image_not_file_drawing(preview):
    html = (preview / "preview.html").read_text(encoding="utf-8")
    parser = _Collector()
    parser.feed(html)
    verified_art = decode_svg_data_uri(parser.img_src[0])
    assert verified_art == ACHIEVEMENT_ART.read_bytes()


def test_card_text_is_escaped():
    card = visual.Card(True, "verificado", "x", "<script>alert(1)</script>", "d",
                       "c", "r", "i", "id", "", "")
    rendered = visual.render_card(card)
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered


def test_unsafe_image_uri_dropped():
    assert visual._safe_image("javascript:alert(1)") == ""
    assert visual._safe_image("https://example.com/x.svg") == ""
