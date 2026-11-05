"""Decodifica e imprime cabeçalho e conteúdo de um JWT, SEM verificar assinatura.

Uso: ``python -m src.inspect out/badge_rs256.jwt``

Serve para ver como a chave pública é referenciada no cabeçalho (``kid``,
``jwk``, ``x5c``, ``x5u``, ``jku``) e quais campos o badge tem. Nada aqui
prova que o token é autêntico.
"""

import base64
import binascii
import json
import sys
from pathlib import Path
from typing import Any

# Membros do cabeçalho JOSE que indicam onde está a chave de verificação.
KEY_REFERENCE_MEMBERS = ("kid", "jwk", "jku", "x5c", "x5u", "x5t", "x5t#S256")


class InspectError(Exception):
    pass


def _b64url_json(segment: str, label: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise InspectError(f"{label} não é JSON em base64url: {exc}") from exc
    if not isinstance(value, dict):
        raise InspectError(f"{label} não é um objeto JSON")
    return value


def decode(token: str) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Devolve (cabeçalho, payload, tamanho da assinatura em bytes)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise InspectError(f"esperado JWT com 3 partes, encontrei {len(parts)}")
    header = _b64url_json(parts[0], "cabeçalho")
    payload = _b64url_json(parts[1], "payload")
    signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    return header, payload, len(signature)


def key_reference(header: dict[str, Any]) -> str:
    present = [m for m in KEY_REFERENCE_MEMBERS if m in header]
    return ", ".join(present) if present else "nenhum (chave precisa vir de fora)"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("uso: python -m src.inspect <arquivo.jwt>", file=sys.stderr)
        return 2
    try:
        header, payload, sig_len = decode(Path(args[0]).read_text())
    except (OSError, InspectError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1

    dump = lambda value: json.dumps(value, indent=2, ensure_ascii=False)  # noqa: E731
    print("ATENÇÃO: assinatura NÃO verificada; isto só decodifica o token.\n")
    print("=== Cabeçalho ===")
    print(dump(header))
    print("\n=== Conteúdo (payload) ===")
    print(dump(payload))
    print("\n=== Resumo ===")
    print(f"  alg:                    {header.get('alg')}")
    print(f"  referência da chave:    {key_reference(header)}")
    issuer = payload.get("issuer")
    print(f"  iss / issuer.id:        {payload.get('iss')} / "
          f"{issuer.get('id') if isinstance(issuer, dict) else issuer}")
    print(f"  sub:                    {payload.get('sub')}")
    print(f"  type:                   {payload.get('type')}")
    print(f"  campos de topo:         {', '.join(payload)}")
    print(f"  assinatura:             {sig_len} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
