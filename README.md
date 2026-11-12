# nfse-giss-assinador-go

Assinador XMLDSig (C14N 1.0 inclusivo, RSA-SHA1/SHA-256) e transmissor SOAP/mTLS para NFS-e no
padrão GISS 2.04/ABRASF. Biblioteca Go genérica — sem lógica de negócio, sem dado de município ou
cliente específico.

## 🔴 `testdata/` é só para TESTE — nunca use nada daí em produção

Todo o conteúdo de `testdata/` (XML, certificados, chaves, senhas) é **sintético e descartável**,
gerado por `tools/gerar_vetores.py` só para validar este pacote. Em especial:

- `testdata/certs/teste.key.pem` é uma chave RSA-2048 **real e válida** no formato PKCS#8 — mas
  gerada só para este repositório, nunca usada para assinar um documento de verdade. O arquivo tem
  o mesmo aviso no próprio cabeçalho.
- Senha dos `.pfx` de teste: `"teste123"` — também fictícia.
- Ver `testdata/README.md` para o detalhe de cada vetor e como foram validados.

**Nunca misture nada de `testdata/` com um certificado real.**

## O `replace` do `goxmldsig` neste `go.mod` só vale quando este módulo é o PRINCIPAL

O `go.mod` deste repositório tem:
```
replace github.com/russellhaering/goxmldsig => github.com/javendisistemas-afk/goxmldsig v1.6.2-...
```
pro fork que corrige o canonicalizador exclusivo (C14N) — usado só por `C14NExclusiva`
(`assinador/guard_c14n.go`); nenhum caminho de produção usa essa variante hoje.

🔴 **Um `replace` só é aplicado quando o módulo que o declara é o MÓDULO PRINCIPAL do build** (regra
dos Go Modules). Se você importar `nfse-giss-assinador-go` como dependência de outro programa, o
`replace` acima **é ignorado** — seu build resolve `goxmldsig` pela versão que o `go.mod` deste
repositório **declara** (`v1.6.1`, upstream, **sem** o patch do C14N exclusivo), a menos que o SEU
próprio `go.mod` declare o mesmo `replace`. Se o seu uso depender de `C14NExclusiva` funcionar
corretamente com namespace herdado de um ancestral fora da sub-árvore assinada, copie o `replace`
acima pro seu próprio `go.mod`.
