"""Gera o badge baked e um preview em HTML autocontido.

Uso: ``python -m src.visual [--alg RS256]``. Grava ``out/badge_baked.svg`` e
``out/preview.html``. A página não usa rede nem JavaScript: a verificação é
feita aqui, pelo Python, no momento em que o HTML é gerado.

O cartão "verificado" mostra os dados e as imagens que vêm da credencial
verificada, nunca do desenho do arquivo (que não é coberto pela assinatura;
ver ``src/experiment.py``). Ao lado, um cartão com um badge adulterado mostra
os dados que ele alega, marcados como não confiáveis, e o motivo da rejeição.
"""

import argparse
import base64
import sys
from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from openbadgeslib.ob3 import OB3VerificationError, OpenBadgeCredential

from .baked import (BAKED_NAME, OUT_DIR, bake, build_visual_credential,
                    extract_token, verify_baked)
from .demo import tamper_jwt_payload
from .experiment import tamper_drawing
from .images import SVG_DATA_PREFIX
from .inspect import decode
from .issue import RECIPIENT_ID, jwt_key_for
from .keys import ALGORITHMS, JwtKey, generate_keys

PREVIEW_NAME = "preview.html"
FORGED_NAME = "Doutorado Honoris"


@dataclass
class Card:
    verified: bool
    status: str             # texto do selo de status
    detail: str             # explicação do status
    name: str
    description: str
    criteria: str
    recipient: str
    issuer_name: str
    issuer_id: str
    art_uri: str            # imagem da conquista (data: URI)
    logo_uri: str           # logo do emissor (data: URI)


def _safe_image(uri: Any) -> str:
    """Só aceita SVG em data: URI base64; qualquer outra coisa vira vazio."""
    return uri if isinstance(uri, str) and uri.startswith(SVG_DATA_PREFIX) else ""


def _svg_uri(svg_bytes: bytes) -> str:
    return SVG_DATA_PREFIX + base64.b64encode(svg_bytes).decode("ascii")


def _recipient(value: str | None) -> str:
    return (value or "").removeprefix("mailto:")


def verified_card(credential: OpenBadgeCredential, key: JwtKey, when: str) -> Card:
    return Card(
        verified=True,
        status="verificado",
        detail=(f"Assinatura {key.alg} válida com a chave pública do emissor; "
                f"destinatário confere. Verificado em {when}."),
        name=credential.achievement.name,
        description=credential.achievement.description,
        criteria=credential.achievement.criteria_narrative,
        recipient=_recipient(credential.recipient_id),
        issuer_name=credential.issuer.name,
        issuer_id=credential.issuer.id,
        art_uri=_safe_image(credential.achievement.image_url),
        logo_uri=_safe_image(credential.issuer.image_url),
    )


def rejected_card(svg_bytes: bytes, error: str, when: str) -> Card:
    """Dados ALEGADOS pelo badge adulterado (decodificados sem verificação)."""
    _, payload, _ = decode(extract_token(svg_bytes))
    achievement = payload.get("credentialSubject", {}).get("achievement", {})
    issuer = payload.get("issuer", {})
    return Card(
        verified=False,
        status="adulterado: rejeitado",
        detail=f"Verificação falhou em {when}: {error}. Os dados deste cartão NÃO são confiáveis.",
        name=str(achievement.get("name", "")),
        description=str(achievement.get("description", "")),
        criteria=str(achievement.get("criteria", {}).get("narrative", "")),
        recipient=_recipient(payload.get("credentialSubject", {}).get("id")),
        issuer_name=str(issuer.get("name", "")),
        issuer_id=str(issuer.get("id", "")),
        # Sem credencial válida, a única imagem disponível é o desenho do arquivo.
        art_uri=_svg_uri(svg_bytes),
        logo_uri=_safe_image(issuer.get("image", {}).get("id")),
    )


def make_tampered(baked_svg: bytes) -> bytes:
    """Badge falsificado: nome da conquista trocado no token e no desenho."""
    token = extract_token(baked_svg)
    forged = tamper_jwt_payload(token, FORGED_NAME)
    return tamper_drawing(baked_svg).replace(token.encode(), forged.encode())


def render_card(card: Card) -> str:
    e = escape
    css = "card ok" if card.verified else "card bad"
    art = (f'<img class="art" src="{e(card.art_uri)}" alt="Imagem da conquista {e(card.name)}">'
           if card.art_uri else '<div class="art missing">sem imagem</div>')
    logo = (f'<img class="logo" src="{e(card.logo_uri)}" alt="Logo de {e(card.issuer_name)}">'
            if card.logo_uri else "")
    return f"""
  <article class="{css}">
    <p class="status">{"✔" if card.verified else "✘"} {e(card.status)}</p>
    {art}
    <h2>{e(card.name)}</h2>
    <p class="description">{e(card.description)}</p>
    <dl>
      <dt>Critério</dt><dd>{e(card.criteria)}</dd>
      <dt>Destinatário</dt><dd>{e(card.recipient)}</dd>
      <dt>Emissor</dt><dd class="issuer">{logo}<span>{e(card.issuer_name)}<br><code>{e(card.issuer_id)}</code></span></dd>
    </dl>
    <p class="detail">{e(card.detail)}</p>
  </article>"""


def render_page(cards: list[Card], generated_at: str) -> str:
    body = "".join(render_card(c) for c in cards)
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<title>Preview do badge (fictício)</title>
<style>
  :root {{ font-family: system-ui, sans-serif; color: #1d2530; background: #f3f5f8; }}
  body {{ margin: 0; padding: 32px 16px; }}
  header, main {{ max-width: 920px; margin: 0 auto; }}
  header h1 {{ margin: 0 0 4px; font-size: 1.5rem; }}
  header p {{ margin: 0 0 24px; color: #5b6573; }}
  main {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; }}
  .card {{ background: #fff; border-radius: 16px; padding: 24px; border: 3px solid;
          box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  .card.ok {{ border-color: #2e7d4f; }}
  .card.bad {{ border-color: #b22222; background: #fff7f7; }}
  .status {{ display: inline-block; margin: 0 0 16px; padding: 4px 12px; border-radius: 999px;
            font-weight: 700; color: #fff; text-transform: uppercase; font-size: .8rem; letter-spacing: .05em; }}
  .ok .status {{ background: #2e7d4f; }}
  .bad .status {{ background: #b22222; }}
  .art {{ display: block; width: 220px; height: 220px; margin: 0 auto 16px; }}
  .bad .art {{ filter: grayscale(60%); opacity: .8; }}
  .missing {{ display: grid; place-items: center; background: #eee; border-radius: 50%; color: #888; }}
  h2 {{ margin: 0 0 8px; text-align: center; }}
  .bad h2, .bad dd, .bad .description {{ text-decoration: line-through; text-decoration-color: #b22222; }}
  .description {{ text-align: center; color: #3c4653; }}
  dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 8px 12px; margin: 16px 0; }}
  dt {{ font-weight: 600; color: #5b6573; }}
  dd {{ margin: 0; overflow-wrap: anywhere; }}
  .issuer {{ display: flex; gap: 10px; align-items: center; }}
  .logo {{ width: 40px; height: 40px; flex: none; }}
  code {{ font-size: .75rem; color: #5b6573; }}
  .detail {{ font-size: .85rem; color: #3c4653; border-top: 1px solid #e3e7ec; padding-top: 12px; margin: 0; }}
  .bad .detail {{ color: #8b1a1a; }}
  footer {{ max-width: 920px; margin: 24px auto 0; font-size: .8rem; color: #5b6573; }}
</style>
</head>
<body>
<header>
  <h1>Open Badges 3.0: preview do badge</h1>
  <p>Dados fictícios (example.com). Verificação feita pelo Python ao gerar esta página, em {escape(generated_at)}.</p>
</header>
<main>{body}
</main>
<footer>
  O desenho de um badge baked não é coberto pela assinatura. Por isso o cartão
  verificado mostra a imagem que vem dentro da credencial assinada, e não o
  desenho do arquivo. Esta página não tem JavaScript nem acessa a rede.
</footer>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alg", choices=ALGORITHMS, default="RS256")
    alg = parser.parse_args(argv).alg

    key = jwt_key_for(alg, generate_keys())
    OUT_DIR.mkdir(exist_ok=True)
    baked_path = OUT_DIR / BAKED_NAME
    baked_path.write_bytes(bake(key, build_visual_credential(key)))
    baked = baked_path.read_bytes()

    when = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S (UTC%:z)")
    try:
        credential = verify_baked(baked, key.public_pem, RECIPIENT_ID)
    except OB3VerificationError as exc:
        print(f"FALHA: o badge baked não foi verificado: {exc}", file=sys.stderr)
        return 1
    cards = [verified_card(credential, key, when)]

    tampered = make_tampered(baked)
    try:
        verify_baked(tampered, key.public_pem, RECIPIENT_ID)
    except OB3VerificationError as exc:
        cards.append(rejected_card(tampered, str(exc), when))
    else:
        print("FALHA: o badge adulterado foi ACEITO", file=sys.stderr)
        return 1

    preview_path = OUT_DIR / PREVIEW_NAME
    preview_path.write_text(render_page(cards, when), encoding="utf-8")

    print(baked_path)
    print(preview_path)
    print(f"verificado:  '{credential.achievement.name}' ({alg}, emissor {key.issuer_id})")
    print(f"adulterado:  '{cards[1].name}' rejeitado ({cards[1].detail.split(': ', 1)[1].split('.')[0]})")
    print(f"abra no navegador: {preview_path.resolve().as_uri()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
