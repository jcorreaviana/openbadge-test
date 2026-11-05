# openbadge-test

Prova de conceito offline de **Open Badges 3.0** e **CLR 2.0**: emissão,
verificação e agrupamento de credenciais verificáveis em padrão aberto.

Todos os dados são fictícios (`example.com`). Não há servidor, banco de dados
nem interface. No fluxo padrão (`EdDSA`) o par de chaves existe só em memória.
Para `RS256` e `ES256` há uma chave de teste persistente, guardada **fora** do
repositório (ver [Chave de teste persistente](#chave-de-teste-persistente)).

## Os padrões

**Open Badges 3.0** (1EdTech) representa uma conquista (um curso, uma
competência) como uma *Verifiable Credential* do W3C. O badge diz quem emitiu,
quem recebeu e o que foi conquistado, e é assinado pelo emissor. Qualquer pessoa
com a chave pública do emissor verifica o badge sem consultar o emissor. A
especificação aceita duas formas de prova:

- **JWT-VC**: o badge vai no payload de um JWT compacto, assinado aqui com `EdDSA`
  (Ed25519, padrão), `RS256` (RSA 2048) ou `ES256` (P-256).
- **Data Integrity**: o badge é um documento JSON-LD com uma prova embutida
  (`eddsa-rdfc-2022`), calculada sobre a forma canônica RDF do documento.

**CLR 2.0** (*Comprehensive Learner Record*, 1EdTech) é um histórico: uma
credencial `ClrCredential` que agrupa vários badges de um mesmo aluno. O CLR
tem sua própria assinatura, e cada badge dentro dele continua sendo um documento
assinado por si só.

O emissor é identificado por um **`did:key`**, derivado da própria chave
pública, então resolver o DID devolve a chave sem acesso à rede. O `did:key`
só aceita Ed25519 e P-256; por isso, em `RS256` o emissor é identificado pela
URL fictícia `https://example.com/issuers/escola-exemplo`.

## Instalação e uso

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python -m src.demo                  # fluxo completo; código 1 se alguma fraude passar
.venv/bin/python -m src.demo --alg RS256      # badges JWT-VC em RS256 (também: ES256)
.venv/bin/python -m src.export --alg RS256    # grava out/badge_rs256.jwt e o verifica
.venv/bin/python -m src.hosting               # gera docs/ (perfil e chave pública do emissor)
.venv/bin/python -m src.export --alg RS256 --hosted  # out/badge_rs256_hosted.jwt, verificado por docs/
.venv/bin/python -m src.inspect out/badge_rs256.jwt   # mostra cabeçalho e conteúdo
.venv/bin/python -m src.visual                # badge baked em SVG + out/preview.html
.venv/bin/python -m src.experiment            # altera o desenho do badge baked e reverifica
.venv/bin/pytest                              # testes, incluindo os negativos
```

O demo grava `out/badge1.jwt` e `out/clr.json`, o export grava
`out/badge_<alg>.jwt` e o visual grava `out/badge_baked.svg` e
`out/preview.html` (a pasta `out/` não vai para o git).

- **`--alg`** (`demo` e `export`): `EdDSA` (padrão do demo), `RS256` (padrão do
  export) ou `ES256`. Vale só para os badges JWT-VC: os badges Data Integrity e o
  CLR usam `eddsa-rdfc-2022`, que exige Ed25519.
- **`src.export`** emite um badge fictício, grava o arquivo, imprime o caminho e
  um resumo de uma linha (algoritmo e emissor) e depois relê o arquivo e o
  verifica com `OB3Verifier` e a chave pública do emissor.
- **`src.inspect`** decodifica o JWT e imprime cabeçalho e conteúdo formatados,
  mais um resumo (algoritmo, como a chave é referenciada, emissor, destinatário).
  **Não verifica a assinatura.**

## Chave de teste persistente

Com `RS256` e `ES256`, a chave vem de `src/keystore.py`:

- Local: `~/.openbadge-test/keys/` (`rsa_private.pem`, `ec_private.pem`), ou a
  pasta indicada em `OPENBADGE_TEST_KEYDIR`.
- É criada na primeira execução e reutilizada nas seguintes, então o emissor e a
  chave pública ficam estáveis entre execuções.
- Pasta com permissão `700` e chave privada com `600`. Se a chave tiver
  permissões mais abertas, o programa se recusa a usá-la.
- O programa se recusa a usar uma pasta dentro do repositório, e um teste
  garante que nenhum arquivo de chave está em `git ls-files`.
- A chave privada nunca é impressa.

> **Aviso:** esta chave é **só para teste**, com dados fictícios. Nunca a reutilize
> para emitir credenciais reais. Para descartá-la, apague `~/.openbadge-test/`.

## Estrutura e o que cada etapa demonstra

| Arquivo | O que demonstra |
| --- | --- |
| `src/keys.py` | Gera um par Ed25519 em memória e deriva o `did:key`. O *verification method* segue o formato `did#fragmento`, onde o fragmento é o próprio identificador multibase (`did:key:z6Mk…#z6Mk…`). Também define o identificador do emissor de cada algoritmo JWT. |
| `src/keystore.py` | Chave de teste RSA/P-256 persistente, fora do repositório. |
| `src/issue.py` | Um emissor (Escola Exemplo), duas conquistas e uma destinatária fictícios. Emite cada badge como JWT-VC e como Data Integrity, e monta o CLR com os badges Data Integrity dentro, assinado com `sign_clr_credential`. No CLR, a destinatária aparece só como hash SHA-256 de `e-mail + salt` (`IdentityObject`). |
| `src/verify.py` | Verifica badges com `OB3Verifier` / `OB3LdpVerifier`, fixando a chave pública do emissor e o destinatário esperado. Verifica o CLR (ver abaixo). Toda falha lança `OB3VerificationError`. |
| `src/demo.py` | Roda o fluxo inteiro, imprime cada etapa, tenta 7 fraudes e confere que todas foram rejeitadas. |
| `src/export.py` | Grava um badge JWT-VC em `out/badge_<alg>.jwt` e o verifica localmente. |
| `src/inspect.py` | Decodifica um JWT sem verificar a assinatura. |
| `src/hosting.py` | Gera o site do emissor em `docs/`, assina badges com `kid` e os verifica só com os arquivos publicados. |
| `docs/` | Site estático para o GitHub Pages: perfil do emissor, chave pública (JWK e JWKS) e `did.json`. |
| `assets/` | Artes fictícias em SVG: logo do emissor e selo da conquista. |
| `src/images.py` | Emissor e conquista com as artes como `data:` URI. |
| `src/baked.py` | Embute a credencial assinada no SVG da conquista e a extrai e verifica. |
| `src/experiment.py` | Altera o desenho do badge baked para ver o que a assinatura cobre. |
| `src/visual.py` | Gera o badge baked e o `out/preview.html`. |
| `tests/test_flow.py` | Emissão, verificação e os casos negativos (EdDSA, Data Integrity e CLR). |
| `tests/test_algorithms.py` | RS256/ES256, keystore, export/inspect e ausência de chaves no git. |
| `tests/test_visual.py` | Artes, badge baked, experimento e preview. |
| `tests/test_hosting.py` | Site do emissor, ausência de campos privados em `docs/`, verificação a partir dos arquivos publicados e casos negativos. |

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

## Aparência do badge

Uma referência visual de como o badge chega a quem o recebe. Tudo é fictício e
offline.

```bash
.venv/bin/python -m src.visual     # padrão RS256 com a chave do keystore; --alg ES256 ou EdDSA
open out/preview.html              # macOS; em outros sistemas, abra o arquivo no navegador
```

### Imagens

`assets/` tem duas artes originais em SVG, de 512x512, feitas só com formas
geométricas e texto, sem fontes externas nem imagens embutidas:

- `issuer-logo.svg`: quadrado com as iniciais "EE" da Escola Exemplo.
- `achievement-python-basico.svg`: selo circular com fitas e o nome da conquista.

As duas vão **dentro da credencial**, nos campos `issuer.image.id` e
`achievement.image.id`, como `data:image/svg+xml;base64,...`. As URLs de
`example.com` não existem, então foi testado se a biblioteca aceita `data:`
URI: aceita, em JWT-VC (RS256 e EdDSA) e em Data Integrity, e a imagem volta
idêntica depois da verificação. O custo é o tamanho: o token RS256 passa de
cerca de 2,7 KB para 5,9 KB. O fluxo do `demo` não mudou e continua sem imagens.

### Badge baked

Um badge *baked* é a imagem do badge com a credencial assinada dentro do
próprio arquivo. `src.visual` usa `sign_into_svg` para pôr o JWT-VC em um
elemento `<openbadges:credential verify="…"/>`, no namespace
`https://purl.imsglobal.org/ob/v3p0`, ao final do SVG da conquista, e grava
`out/badge_baked.svg`. Depois lê o arquivo de volta, extrai o token com
`extract_token_from_svg` e o verifica com `OB3Verifier`. O navegador ignora o
elemento extra, então o SVG continua abrindo como uma imagem normal.

A chave e o algoritmo são os do `export`: RS256 com a chave do keystore por
padrão, então o badge salvo pode ser verificado de novo em outra execução.

### Preview em HTML

`out/preview.html` é uma página única e autocontida: sem JavaScript, sem
acesso à rede (uma Content-Security-Policy bloqueia tudo que não for imagem
`data:` e CSS embutido) e com as imagens embutidas. Ela mostra dois cartões:

- **Verificado:** desenho da conquista, logo do emissor, nome, descrição,
  critério, destinatário e status, com data e hora da verificação, que o Python
  fez ao gerar a página. Os dados e as imagens vêm da **credencial verificada**,
  não do desenho do arquivo (ver o experimento abaixo).
- **Adulterado: rejeitado:** um badge com o nome da conquista trocado para
  "Doutorado Honoris" no token e no desenho. A verificação falha com
  `Invalid signature`, e o cartão mostra o que o badge *alega*, riscado e
  marcado como não confiável.

A data e hora são as da geração da página. Abrir o HTML depois não verifica
nada de novo: para atualizar, rode `src.visual` outra vez.

### Experimento: o que a assinatura cobre

`python -m src.experiment` altera o **desenho** de `out/badge_baked.svg` sem
tocar no elemento `<openbadges:credential verify="…"/>` e verifica de novo.
Resultado observado com `openbadgeslib` 4.6.3, em RS256:

| Alteração | Verificação |
| --- | --- |
| Nenhuma (original) | passa |
| Cor do selo (verde → vermelho) e texto visível ("Python Básico" → "Doutorado Honoris") | **passa** |
| Elemento da credencial copiado para outro SVG (o logo do emissor) | **passa** |
| Controle: 1 caractere do token alterado | rejeitada (`Invalid signature`) |

**O que isso significa:** a assinatura cobre só o token JWT-VC, ou seja, os
dados da credencial. O desenho do SVG é apenas o envelope que carrega o token,
e qualquer um pode redesenhá-lo sem invalidar nada. Um badge baked que diz
"Doutorado" na imagem pode carregar, validamente, uma credencial de "Python
Básico".

Por isso, quem exibe ou confere um badge deve confiar no **conteúdo verificado**
(nome, descrição, critério, emissor e destinatário) e não no desenho do arquivo.
Aqui, a imagem da conquista também viaja **dentro** da credencial, como
`data:` URI assinado, e é essa imagem que o preview mostra, não o desenho do
arquivo. Mesmo assim, ela só prova qual imagem o emissor associou à conquista.
Não prova que o arquivo que alguém mostra é essa mesma imagem.

## Validar com um verificador externo

Objetivo: submeter um badge ao validador público de Open Badges 3.0 da 1EdTech.

### Resultado registrado

| | |
| --- | --- |
| Validador | Validador público de Open Badges 3.0 da 1EdTech (OB30Inspector). A versão não foi registrada. |
| Data | 2026-11-05 |
| Arquivo | `out/badge_rs256.jwt`, gerado por `src.export --alg RS256` depois da correção do `\n` |
| Badge | `RS256`, chave pública RSA embutida no `jwk` do cabeçalho, sem `kid`; emissor `https://example.com/issuers/escola-exemplo`, sem nada publicado |
| Resultado | **VALID**: 13 verificações, 0 fatais, 0 erros, 0 avisos, 0 exceções |

Antes disso, no mesmo dia, o mesmo tipo de badge tinha recebido um resultado
fatal no `ExternalProofProbe` ("JWT Invalid signature ... SHA256withRSA"). A
causa era a **quebra de linha no fim do arquivo**, que o validador lia como parte
da assinatura (diagnóstico em [Emissor hospedado](#emissor-hospedado)). A
correção, gravar o JWT sem `\n` final, está no `src.export` e no `src.demo`. Entre
os dois envios, essa foi a única mudança que afeta o conteúdo do badge `RS256`
comum (o `export` também foi reorganizado para o `--hosted`, sem mudar esse
badge), e a chave do keystore era a mesma.

**O que esse resultado prova:** o validador aceita a estrutura do badge (as 13
verificações dele) e a assinatura confere com a chave pública **embutida no
próprio token** (`jwk`).

**O que ele não prova:**

- que a chave do `jwk` pertence ao emissor declarado. Quem tiver qualquer par de
  chaves pode assinar um token, embutir a própria chave pública no `jwk` e passar
  na mesma verificação, porque o emissor `example.com` não publica nada que o
  ligue à chave;
- que o emissor existe ou é confiável.

**O que não foi testado no validador:** badge `EdDSA`, badge `ES256`, badge com
`kid` hospedado (`export --hosted`) e badge baked em SVG.

### Como submeter

1. Gere o badge e confira que ele é verificado localmente:

   ```bash
   .venv/bin/python -m src.export --alg RS256
   ```

   A última linha deve ser `verificado localmente com OB3Verifier (chave pública keystore)`.
2. Inspecione o que será enviado:

   ```bash
   .venv/bin/python -m src.inspect out/badge_rs256.jwt
   ```

3. Abra o validador e envie `out/badge_rs256.jwt` como arquivo, ou cole o
   conteúdo dele (uma linha, o JWT compacto `xxxxx.yyyyy.zzzzz`).
4. Anote o resultado em [Resultado registrado](#resultado-registrado): data,
   versão do validador, algoritmo e mensagens de erro ou aviso.

### Como o badge referencia a chave pública

Conferido com `src.inspect` em um badge `RS256` gerado:

- O cabeçalho tem só `alg`, `typ` e **`jwk`**: a chave pública RSA completa
  (`kty`, `n`, `e`) vai embutida no token. Não há `kid`, `jku`, `x5c` nem `x5u`.
- O `jwk` é a mesma chave pública do keystore, e não traz parâmetros privados.
- `iss` e `issuer.id` são `https://example.com/issuers/escola-exemplo`, uma URL
  fictícia que não publica nenhum perfil, DID ou JWKS.

O que isso significa para um validador externo:

- **Para checar a assinatura**, basta o `jwk` do próprio cabeçalho, sem rede.
- **Para ligar a chave ao emissor**, o token não oferece nada que dê para
  resolver: não há `kid` apontando para um documento, e a URL do emissor não
  existe. O validador da 1EdTech **não exigiu** buscar a chave nem o perfil: o
  badge passou só com o `jwk` (ver [Resultado registrado](#resultado-registrado)).
  Para ligar a chave a um emissor real, o perfil e a chave são publicados em uma
  URL (ver [Emissor hospedado](#emissor-hospedado)).
- Localmente, a verificação usa a chave fixada do keystore e **ignora** o `jwk`
  do cabeçalho. Um teste confirma que um token assinado por outra chave, com essa
  outra chave no `jwk`, é rejeitado.

## Emissor hospedado

### O que o validador acusou

Em 2026-11-05, `out/badge_rs256.jwt` e `out/badge1.jwt` foram enviados ao
validador público de Open Badges 3.0 da 1EdTech (OB30Inspector). Os dois
relatórios foram idênticos: 13 verificações, nenhum erro ou aviso e um único
resultado fatal, do `ExternalProofProbe`:

```
Error verifying jwt signature: JWT Invalid signature. Reason: The Token's
Signature resulted invalid when verified using the Algorithm: SHA256withRSA
```

Diagnóstico, feito lendo o código público do validador
(`1EdTech/digital-credentials-public-validator`) e do `java-jwt` 3.19.2 que ele
usa. O validador **não foi executado** localmente (não há JDK aqui).

- O `ExternalProofProbe` aceita só `alg` `RS256` ou `ES256` e checa isso
  **antes** de usar a chave. Um token `EdDSA` seria recusado com outra mensagem
  ("alg must be present..."). Então o `badge1.jwt` enviado deve ter sido gerado
  com `demo --alg RS256`. O `badge1.jwt` local atual é `EdDSA`, mas foi regravado
  depois do envio, então isso não dá para confirmar.
- Com `jwk` no cabeçalho, o validador monta a chave RSA a partir de `n` e `e`.
  O `jwk` dos nossos badges é a mesma chave do keystore (conferido).
- O validador guarda o **conteúdo bruto do arquivo** como JWT, sem `trim`. Os
  arquivos terminavam com `\n`, que entrava no segmento da assinatura. O
  `Base64.getUrlDecoder()` do Java recusa o `\n`, e o `RSAAlgorithm.verify` do
  `java-jwt` converte esse erro exatamente na mensagem acima.
- Localmente, o PyJWT também rejeita o arquivo com o `\n` ("Invalid crypto
  padding"). O `export` só passava porque verificava `read_text().strip()`.

Correção: `export` e `demo` gravam o JWT sem `\n` final, e o `export` verifica o
arquivo exatamente como foi gravado. Um teste cobre isso.

Depois da correção, o `out/badge_rs256.jwt` (chave no `jwk`) foi reenviado e o
resultado foi **VALID**, o que confirma o diagnóstico (ver
[Resultado registrado](#resultado-registrado)).

### Badge hospedado

Para o caso de o validador também precisar buscar a chave do emissor, há um
segundo badge cuja chave é publicada no GitHub Pages:

- `docs/issuer.json`: perfil do emissor (`Profile` OB 3.0 em JSON-LD), com `id`
  igual à própria URL.
- `docs/issuer-key.json`: a chave pública como **um JWK**. É o alvo do `kid`. A
  especificação OB 3.0 (§8.2.3) define o `kid` como uma URI que, ao ser
  desreferenciada, devolve um JWK, e o validador lê a resposta como um JWK (não
  como um JWKS).
- `docs/jwks.json`: a mesma chave em um JWK Set.
- `docs/did.json`: `did:web:jcorreaviana.github.io:openbadge-test` com a mesma
  chave (`JsonWebKey2020`). O `did:key` não aceita RSA, mas o `did:web` aceita,
  e a resolução foi testada com a própria biblioteca. O badge não usa o
  `did.json`; ele está publicado só como alternativa.

O `out/badge_rs256_hosted.jwt` tem cabeçalho `{"alg": "RS256", "kid":
".../issuer-key.json", "typ": "JWT"}`, **sem `jwk`**, e `iss` = `issuer.id` =
`.../issuer.json`. O `export --hosted` verifica o badge **só com os arquivos de
`docs/`**, sem o keystore: `kid` → JWK, a chave tem que estar no JWKS e no
`did.json`, a assinatura é conferida e o `issuer.id` tem que ser o `id` do perfil.

A URL base é `https://jcorreaviana.github.io/openbadge-test`. Para trocá-la, use
`--base-url` ou `OPENBADGE_BASE_URL` (no `src.hosting` e no `export --hosted`).
Os arquivos de `docs/` contêm só a chave pública, e um teste falha se aparecer
qualquer campo privado (`d`, `p`, `q`, `dp`, `dq`, `qi`).

### Passo a passo

1. Gere o site e o badge, e confira a verificação a partir de `docs/`:

   ```bash
   .venv/bin/python -m src.hosting
   .venv/bin/python -m src.export --alg RS256 --hosted
   ```

   A última linha deve começar com `verificado a partir de .../docs/`. Se a chave
   do keystore mudar, rode o `src.hosting` de novo e versione o novo `docs/`.
2. Faça o push da `main` com a pasta `docs/`.
3. No GitHub, em **Settings → Pages**, escolha **Source: Deploy from a branch**,
   **Branch: `main`**, pasta **`/docs`**, e salve.
4. Espere o deploy (aba **Actions**, workflow *pages build and deployment*) e
   confira que os arquivos respondem:

   ```bash
   curl -fsS https://jcorreaviana.github.io/openbadge-test/issuer-key.json
   curl -fsS https://jcorreaviana.github.io/openbadge-test/issuer.json
   curl -fsS https://jcorreaviana.github.io/openbadge-test/did.json
   ```

5. Envie `out/badge_rs256_hosted.jwt` (chave pelo `kid`) ao validador. Isso
   testa a busca da chave publicada.
6. Registre aqui a data e o resultado.

> **Status:** a correção do `\n` já foi testada no validador, com o badge de
> chave no `jwk` (**VALID**). O badge hospedado (`--hosted`) **ainda não foi
> testado** no validador, e o GitHub Pages ainda não foi ativado.

## Limitações

- No fluxo `EdDSA`, as chaves são efêmeras: cada execução gera um emissor novo, e
  um badge salvo em `out/` não pode ser verificado numa execução futura. Em
  `RS256`/`ES256` a chave do keystore é estável.
- `did:key` prova que a assinatura bate com a chave, não quem é o dono da chave.
  Aqui a confiança vem de o verificador receber a chave pública diretamente. O
  emissor `RS256` em URL fictícia também não tem nada que o ligue à chave. O
  emissor hospedado liga a chave ao perfil só por estarem no mesmo site
  (confiança em DNS e TLS do GitHub Pages).
- Os badges trazem o e-mail em texto claro em `credentialSubject.id`; só o CLR
  usa o e-mail com hash.
- Sem revogação (`verify_status_list=False`, nenhum `credentialStatus`).
- No CLR, todos os membros são do mesmo emissor e verificados com a mesma chave.
- A verificação do CLR lê os campos do JSON depois da prova do envelope. A
  biblioteca alerta que a prova Data Integrity cobre o grafo RDF, não o JSON
  literal. Os membros passam pela validação completa do `OB3LdpVerifier`, mas o
  envelope não tem uma validação equivalente de forma JSON-LD.
- Parte visual: só SVG baked (PNG baked não foi feito), só JWT-VC baked (não
  Data Integrity), e o desenho do arquivo não é coberto pela assinatura. O
  status do preview é uma foto do momento em que a página foi gerada.
