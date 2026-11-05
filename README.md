# openbadge-test

Prova de conceito offline de **Open Badges 3.0** e **CLR 2.0**: emissão,
verificação e agrupamento de credenciais verificáveis em padrão aberto.

Todos os dados são fictícios (`example.com`). Não há servidor, banco de dados
nem interface, e nenhuma chave é gravada em disco: o par de chaves existe só
em memória durante a execução.

## Os padrões

**Open Badges 3.0** (1EdTech) representa uma conquista (um curso, uma
competência) como uma *Verifiable Credential* do W3C. O badge diz quem emitiu,
quem recebeu e o que foi conquistado, e é assinado pelo emissor. Qualquer pessoa
com a chave pública do emissor verifica o badge sem consultar o emissor. A
especificação aceita duas formas de prova:

- **JWT-VC**: o badge vai no payload de um JWT compacto, assinado aqui com `EdDSA`
  (Ed25519).
- **Data Integrity**: o badge é um documento JSON-LD com uma prova embutida
  (`eddsa-rdfc-2022`), calculada sobre a forma canônica RDF do documento.

**CLR 2.0** (*Comprehensive Learner Record*, 1EdTech) é um histórico: uma
credencial `ClrCredential` que agrupa vários badges de um mesmo aluno. O CLR
tem sua própria assinatura, e cada badge dentro dele continua sendo um documento
assinado por si só.

O emissor é identificado por um **`did:key`**, derivado da própria chave
pública, então resolver o DID devolve a chave sem acesso à rede.

## Instalação e uso

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python -m src.demo   # fluxo completo; sai com código 1 se alguma fraude passar
.venv/bin/pytest               # testes, incluindo os negativos
```

O demo grava `out/badge1.jwt` e `out/clr.json` (a pasta `out/` não vai para o git).

## Estrutura e o que cada etapa demonstra

| Arquivo | O que demonstra |
| --- | --- |
| `src/keys.py` | Gera um par Ed25519 em memória e deriva o `did:key`. O *verification method* segue o formato `did#fragmento`, onde o fragmento é o próprio identificador multibase (`did:key:z6Mk…#z6Mk…`). |
| `src/issue.py` | Um emissor (Escola Exemplo), duas conquistas e uma destinatária fictícios. Emite cada badge como JWT-VC e como Data Integrity, e monta o CLR com os badges Data Integrity dentro, assinado com `sign_clr_credential`. No CLR, a destinatária aparece só como hash SHA-256 de `e-mail + salt` (`IdentityObject`). |
| `src/verify.py` | Verifica badges com `OB3Verifier` / `OB3LdpVerifier`, fixando a chave pública do emissor e o destinatário esperado. Verifica o CLR (ver abaixo). Toda falha lança `OB3VerificationError`. |
| `src/demo.py` | Roda o fluxo inteiro, imprime cada etapa, tenta 7 fraudes e confere que todas foram rejeitadas. |
| `tests/test_flow.py` | Emissão, verificação e os casos negativos. |

### Fraudes testadas

| Fraude | Onde é pega |
| --- | --- |
| Nome da conquista alterado no payload do JWT | assinatura do JWT |
| Badge assinado pela chave de outro emissor, dizendo ser do emissor legítimo | assinatura do JWT (a chave do emissor é fixada pelo verificador, nunca lida do token) |
| Badge apresentado por outra pessoa | `expected_recipient` |
| Nome de conquista alterado dentro do CLR | prova do CLR |
| Badge membro alterado e o CLR **reassinado** | verificação do badge membro |
| CLR verificado com a chave errada / DID de emissor errado | prova do CLR / vínculo emissor-chave |
| CLR apresentado por outra pessoa | hash do e-mail no `identifier` |

### Verificação do CLR

A biblioteca não tem um verificador de alto nível para CLR, então
`verify_clr` faz:

1. Verifica a prova do envelope com `verify_data_integrity_proof` e
   `extra_contexts=bundled_clr_contexts()`. Sem esse contexto (fixado por hash
   SHA-256), a verificação falha, porque a biblioteca nunca baixa contextos.
2. Confere o tipo `ClrCredential`, e que o emissor e o `verificationMethod` da
   prova pertencem ao DID esperado.
3. Confere `validFrom` / `validUntil`.
4. Confere que algum `identifier` corresponde ao e-mail esperado (recalcula o
   hash com o salt do próprio identifier).
5. **Verifica cada badge membro** com `OB3LdpVerifier`, com a mesma chave e
   destinatário.

O passo 5 é necessário, não só uma precaução extra: o teste
`test_clr_tampered_member_inside_resigned_envelope_rejected` mostra que um CLR
com um membro adulterado e o envelope reassinado **passa** no passo 1. Só a
assinatura do próprio membro denuncia a adulteração.

### Formato do `expected_recipient`

Foram testadas as duas formas, e a biblioteca aceita ambas (normaliza
`ana.souza@example.com` para `mailto:ana.souza@example.com`, sem diferenciar
maiúsculas). **O formato fixado no código é com prefixo:
`mailto:ana.souza@example.com`**, que é exatamente o valor de
`credentialSubject.id` nos badges (`RECIPIENT_ID` em `src/issue.py`). O teste
`test_expected_recipient_with_and_without_mailto` garante que a forma sem prefixo
continua equivalente.

## Limitações

- Chaves efêmeras: cada execução gera um emissor novo. Não há como verificar,
  numa execução futura, um badge salvo em `out/`.
- `did:key` prova que a assinatura bate com a chave, não quem é o dono da chave.
  Aqui a confiança vem de o verificador receber a chave pública diretamente.
- Os badges trazem o e-mail em texto claro em `credentialSubject.id`; só o CLR
  usa o e-mail com hash.
- Sem revogação (`verify_status_list=False`, nenhum `credentialStatus`).
- No CLR, todos os membros são do mesmo emissor e verificados com a mesma chave.
- A verificação do CLR lê os campos do JSON depois da prova do envelope. A
  biblioteca alerta que a prova Data Integrity cobre o grafo RDF, não o JSON
  literal. Os membros passam pela validação completa do `OB3LdpVerifier`, mas o
  envelope não tem uma validação equivalente de forma JSON-LD.
