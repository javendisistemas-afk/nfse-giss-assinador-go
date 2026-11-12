# Vetores de teste — assinador XMLDSig, GISS 2.04

**TUDO AQUI É DE TESTE.** A chave e o certificado foram gerados só para este
pacote (CN `EMPRESA TESTE LTDA:11222333000181`, dados fictícios). Senha dos PFX:
`teste123`. **Nunca use estes arquivos em produção e nunca misture com o
certificado real da empresa.** O certificado real fica FORA de qualquer repositório.

## O que tem
| Pasta/arquivo | Para quê |
|---|---|
| `certs/teste.key.pem`, `teste.crt.pem`, `teste.crt.der` | chave (PKCS#8) e certificado de teste, para assinar sem PFX |
| `certs/teste-legado-3des.pfx`, `teste-legado-rc2.pfx`, `teste-moderno-aes.pfx` | mesmo par em 3 formatos de PFX. Servem para descobrir qual o leitor de PFX do Go aguenta (certificados reais costumam ser 3DES/RC2 antigos ou AES novos) |
| `xml/lote-sem-assinatura-{a,b}.xml` | ENTRADA do assinador (lote com 2 RPS, XSD-válido) |
| `xml/lote-assinado-{a,b}.xml` | SAÍDA esperada, byte a byte |
| `xml/passos/*.c14n` | bytes canonicalizados de cada alvo e de cada `SignedInfo` (para achar onde uma divergência começa) |
| `c14n/` + `manifesto.json` | 10 casos pequenos de C14N inclusivo 1.0 (entrada, `alvo_id`, saída esperada) |
| `negativos/` | documentos adulterados que DEVEM falhar, com o resultado esperado em `golden.json` |
| `golden.json` | digests e SignatureValue esperados, resultado esperado dos negativos |
| `gerar_vetores.py` | gerador (reproduzível e auditável) |

## Variantes
- **A**: `<ds:Signature>` com prefixo, `xmlns:ds` declarado na raiz.
- **B**: `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` (namespace padrão declarado na própria Signature; raiz SEM `xmlns:ds`).

## Regras usadas (Manual GISS V1.7, tabela XS01–XS21, XSD 2.04)
C14N inclusivo `xml-c14n-20010315` sem comentários · `rsa-sha1` · digest `sha1` ·
transforms `enveloped-signature` e `xml-c14n` (nesta ordem — a ordem exigida pela
GISS não está confirmada) · `KeyInfo` só com `X509Data/X509Certificate` ·
`Reference URI="#Id"` · XML compacto, UTF-8 ·
assina cada RPS (Signature irmã de `InfDeclaracaoPrestacaoServico`, dentro de `Rps`)
e depois o lote (Signature filha da raiz, depois de `LoteRps`).

## Como estes vetores foram validados (não confie só neles: confira)
1. Os XML passam no **XSD oficial GISS 2.04** (`enviar-lote-rps-envio-v2_04.xsd`).
2. As assinaturas de A **e** B são aprovadas pelo **`xmlsec1` 1.2.39** (as 3 em cada arquivo).
3. Os 3 negativos são reprovados pelo `xmlsec1` exatamente onde `golden.json` diz.
4. Os 10 casos de C14N foram conferidos à mão contra a especificação.
5. O `signxml` (biblioteca de terceiros) também aprovou a variante A; recusou a B por
   limitação dele com Signature em namespace padrão (não por erro de assinatura).

## Armadilhas que já apareceram (leia antes de escrever o C14N)
1. **C14N inclusivo copia TODOS os `xmlns` em escopo para o elemento raiz do trecho,
   inclusive os NÃO usados** (ex.: `xmlns:xsi`). O digest depende do documento
   final montado, não do trecho isolado.
2. O `enveloped-signature` remove **só a Signature que contém aquela Reference**.
   As assinaturas dos RPS ficam DENTRO de `LoteRps` e entram no digest do lote.
   Por isso a ordem é: RPS 1, RPS 2, lote por último.
3. **O `lxml`/`libxml2` erra o C14N de SUB-ÁRVORE** quando o `xmlns` padrão vem de um
   ancestral fora do trecho: emite `xmlns=""` espúrio nos filhos. O gerador contorna
   isso, e o `xmlsec1` foi o árbitro. **Se o seu resultado divergir de um vetor,
   NÃO ajuste o teste para bater com a sua saída: pare e compare os bytes.**
4. RSA PKCS#1 v1.5 é determinístico: com a mesma chave, o `SignatureValue` do Go tem
   de ser idêntico ao do vetor.

## Não verificado aqui
Não havia Go neste ambiente. Ninguém rodou ainda o `x/crypto/pkcs12` contra os PFX
(o formato AES/PBES2 pode não ser suportado por ele — isso é um palpite, não um fato).
