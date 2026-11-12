module github.com/javendisistemas-afk/nfse-giss-assinador-go

go 1.26.5

require (
	github.com/beevik/etree v1.8.1
	github.com/russellhaering/goxmldsig v1.6.1
	software.sslmate.com/src/go-pkcs12 v0.7.3
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	golang.org/x/crypto v0.11.0 // indirect
)

// Patch proprio corrigindo o canonicalizador exclusivo (C14N) pra subir pelos ancestrais reais do
// elemento, igual ao caminho inclusivo ja faz — sem isso, assinar um sub-elemento cujo namespace
// (prefixo nomeado ou padrao) foi declarado so num ancestral fora do subarvore assinada falha ou
// produz forma canonica errada sem erro. So usado por C14NExclusiva (nenhum caller de producao usa
// esse valor hoje); fork publico, confirmado alcancavel sem credencial.
replace github.com/russellhaering/goxmldsig => github.com/javendisistemas-afk/goxmldsig v1.6.2-0.20261108173718-4281c71efdfd
