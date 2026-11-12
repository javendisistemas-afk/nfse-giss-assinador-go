// Package assinador assina XML de NFS-e (GISS 2.04) com XMLDSig: rsa-sha1,
// digest sha1, C14N configurável (ver tipo C14N — inclusiva por padrão/compatibilidade,
// exclusiva disponível pro DPS/ADN) sem comentários, transforms enveloped-signature + c14n,
// KeyInfo só com X509Certificate.
package assinador

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Namespace controla como o elemento Signature declara o namespace XMLDSig.
type Namespace int

const (
	// PrefixoDS gera <ds:Signature>, assumindo que xmlns:ds já está em escopo
	// (normalmente declarado na raiz do documento).
	PrefixoDS Namespace = iota
	// PadraoNaSignature gera <Signature xmlns="...xmldsig#">, declarando o
	// namespace diretamente no próprio elemento Signature (raiz do documento
	// não precisa declarar nada).
	PadraoNaSignature
)

// C14N controla qual canonicalização XML a assinatura DECLARA (CanonicalizationMethod/Transform)
// e USA DE FATO pro digest/assinatura — as duas coisas juntas, nunca uma só (declarar uma e
// assinar com outra produz um XML inconsistente, que um verificador rejeitaria).
//
// 🔑 F7.0/F7.2a: até aqui só existia C14N10Rec (inclusiva), hardcoded. O parâmetro foi
// acrescentado (em vez de trocar o valor fixo) porque Assinar/AssinarDocumento/AssinarRpsInterno
// ainda são o caminho do fluxo GISS/RPS — mesmo com nfse_emissao em off, continuam compilados e
// testados contra golden byte-a-byte que dependem do C14N INCLUSIVO. Trocar o valor fixo mudaria
// a saída desse caminho em silêncio; parametrizar preserva o comportamento de todo caller
// existente (todos passam C14NInclusiva) e deixa o DPS/ADN (fatia futura) escolher
// C14NExclusiva explicitamente.
type C14N int

const (
	// C14NInclusiva usa a Recommendation inclusiva (xml-c14n-20010315) — comportamento histórico
	// de todo caller hoje (GISS/RPS). canonicalizadorDe usa dsig.MakeC14N10RecCanonicalizer().
	C14NInclusiva C14N = iota
	// C14NExclusiva usa xml-exc-c14n# (dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList) — achado
	// de campo pro ADN (F7.0: prática relatada, NÃO documento oficial).
	//
	// 🔴 MEDIDO NA F7.2a, NÃO USÁVEL AINDA: com PrefixoDS (a única variante usada em produção),
	// Assinar E AssinarDocumento FALHAM com "undeclared namespace prefix" — goxmldsig@v1.6.1
	// resolve namespace só pelos atributos do PRÓPRIO elemento canonicalizado
	// (etreeutils.NSContext.SubContext), nunca subindo por ancestrais; isso quebra tanto um alvo
	// com prefixo herdado da raiz (Assinar) quanto o SignedInfo, que herda xmlns:ds do Signature
	// que o envolve, nunca o redeclarando (AssinarDocumento). Ver c14n_exclusiva_test.go. Nenhum
	// caller de produção usa este valor.
	C14NExclusiva
)

const nsXMLDSig = "http://www.w3.org/2000/09/xmldsig#"

const (
	algC14NInclusiva      = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	algC14NExclusiva      = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algRSASHA1            = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algSHA1               = "http://www.w3.org/2000/09/xmldsig#sha1"
	algEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// algC14NDe devolve a URI que CanonicalizationMethod/Transform devem declarar pra `c14n`.
func algC14NDe(c14n C14N) string {
	if c14n == C14NExclusiva {
		return algC14NExclusiva
	}
	return algC14NInclusiva
}

// canonicalizadorDe devolve o Canonicalizer real (goxmldsig) que corresponde a `c14n` — a MESMA
// escolha que algC14NDe declara, nunca uma diferente (ver comentário do tipo C14N).
func canonicalizadorDe(c14n C14N) dsig.Canonicalizer {
	if c14n == C14NExclusiva {
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	}
	return dsig.MakeC14N10RecCanonicalizer()
}

// Assinar assina, em ORDEM, cada elemento identificado por um atributo
// Id em alvos, inserindo um <Signature> como ÚLTIMO FILHO do PAI de cada
// elemento (Signature irmã do elemento referenciado, não descendente dele).
//
// Função pura: recebe o XML de entrada e a chave/certificado já carregados,
// devolve o XML assinado. Não lê arquivo nem rede.
func Assinar(xmlEntrada []byte, alvos []string, chave *rsa.PrivateKey, certificado *x509.Certificate, ns Namespace, c14n C14N) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlEntrada); err != nil {
		return nil, fmt.Errorf("assinador: XML de entrada inválido: %w", err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("assinador: XML de entrada sem elemento raiz")
	}

	canon := canonicalizadorDe(c14n)
	certB64 := base64.StdEncoding.EncodeToString(certificado.Raw)

	for _, id := range alvos {
		if err := assinarUm(doc, canon, id, chave, certB64, ns, c14n); err != nil {
			return nil, err
		}
	}

	saida, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("assinador: falha ao serializar XML assinado: %w", err)
	}
	return saida, nil
}

func assinarUm(doc *etree.Document, canon dsig.Canonicalizer, id string, chave *rsa.PrivateKey, certB64 string, ns Namespace, c14n C14N) error {
	return assinarUmNo(doc, canon, id, false, chave, certB64, ns, c14n)
}

// assinarUmNo: rpsInterno=true (F4.21, variante em teste) insere a Signature no pai de
// InfDeclaracaoPrestacaoServico (o Rps externo), mantendo o digest no próprio elemento com Id.
func assinarUmNo(doc *etree.Document, canon dsig.Canonicalizer, id string, rpsInterno bool, chave *rsa.PrivateKey, certB64 string, ns Namespace, c14n C14N) error {
	alvo := acharPorID(doc.Root(), id)
	if alvo == nil {
		return fmt.Errorf("assinador: elemento com Id=%q não encontrado", id)
	}
	pai := alvo.Parent()
	if rpsInterno && pai != nil {
		pai = pai.Parent()
	}
	if pai == nil {
		return fmt.Errorf("assinador: elemento com Id=%q é a raiz do documento, não pode receber Signature irmã", id)
	}

	if err := verificarConstrucaoSuportada(alvo); err != nil {
		return fmt.Errorf("assinador: alvo %q: %w", id, err)
	}

	// 1) digest do alvo, no estado ATUAL do documento (pode já conter
	// Signatures de alvos assinados antes, se forem descendentes do alvo —
	// é o caso do lote em relação aos RPS).
	alvoC14n, err := canon.Canonicalize(alvo)
	if err != nil {
		return fmt.Errorf("assinador: C14N do alvo %q: %w", id, err)
	}
	digestAlvo := sha1.Sum(alvoC14n)

	// 2) monta o esqueleto do Signature e anexa na posição final ANTES de
	// preencher os valores — assim o C14N do SignedInfo (passo 3) herda o
	// contexto de namespace correto dos ancestrais reais do documento.
	sig := montarEsqueleto(ns, c14n)
	if ns == PrefixoDS && !prefixoDeclarado(pai, "ds") {
		// medido na F4.2b: o gerador de referência não declara xmlns:ds na raiz
		// (só xmlns:p/xmlns:p1). Sem isto, a lib assina e canonicaliza
		// normalmente (C14N10Rec não valida prefixo não declarado), e o XML
		// de saída fica com "ds:" usado sem NENHUMA declaração no documento
		// — malformado do ponto de vista de namespaces, mas passava batido.
		sig.CreateAttr("xmlns:ds", nsXMLDSig)
	}
	pai.AddChild(sig)

	signedInfo := sig.SelectElement(tag(ns, "SignedInfo"))
	referencia := signedInfo.SelectElement(tag(ns, "Reference"))
	referencia.CreateAttr("URI", "#"+id)
	referencia.SelectElement(tag(ns, "DigestValue")).SetText(base64.StdEncoding.EncodeToString(digestAlvo[:]))

	// 3) assina o SignedInfo já anexado ao documento.
	signedInfoC14n, err := canon.Canonicalize(signedInfo)
	if err != nil {
		return fmt.Errorf("assinador: C14N do SignedInfo (alvo %q): %w", id, err)
	}
	hashSignedInfo := sha1.Sum(signedInfoC14n)
	assinatura, err := rsa.SignPKCS1v15(rand.Reader, chave, crypto.SHA1, hashSignedInfo[:])
	if err != nil {
		return fmt.Errorf("assinador: assinatura RSA-SHA1 (alvo %q): %w", id, err)
	}

	sig.SelectElement(tag(ns, "SignatureValue")).SetText(base64.StdEncoding.EncodeToString(assinatura))

	x509CertEl := sig.FindElement(tag(ns, "KeyInfo") + "/" + tag(ns, "X509Data") + "/" + tag(ns, "X509Certificate"))
	x509CertEl.SetText(certB64)

	return nil
}

// montarEsqueleto cria (DESANEXADO) a árvore completa do Signature, com
// DigestValue/SignatureValue/X509Certificate vazios — preenchidos depois.
func montarEsqueleto(ns Namespace, c14n C14N) *etree.Element {
	sig := etree.NewElement(tag(ns, "Signature"))
	if ns == PadraoNaSignature {
		sig.CreateAttr("xmlns", nsXMLDSig)
	}

	algC14NAtual := algC14NDe(c14n)

	signedInfo := sig.CreateElement(tag(ns, "SignedInfo"))

	c14nMethod := signedInfo.CreateElement(tag(ns, "CanonicalizationMethod"))
	c14nMethod.CreateAttr("Algorithm", algC14NAtual)

	sigMethod := signedInfo.CreateElement(tag(ns, "SignatureMethod"))
	sigMethod.CreateAttr("Algorithm", algRSASHA1)

	referencia := signedInfo.CreateElement(tag(ns, "Reference"))
	transforms := referencia.CreateElement(tag(ns, "Transforms"))
	t1 := transforms.CreateElement(tag(ns, "Transform"))
	t1.CreateAttr("Algorithm", algEnvelopedSignature)
	t2 := transforms.CreateElement(tag(ns, "Transform"))
	t2.CreateAttr("Algorithm", algC14NAtual)
	digestMethod := referencia.CreateElement(tag(ns, "DigestMethod"))
	digestMethod.CreateAttr("Algorithm", algSHA1)
	referencia.CreateElement(tag(ns, "DigestValue"))

	sig.CreateElement(tag(ns, "SignatureValue"))

	keyInfo := sig.CreateElement(tag(ns, "KeyInfo"))
	x509Data := keyInfo.CreateElement(tag(ns, "X509Data"))
	x509Data.CreateElement(tag(ns, "X509Certificate"))

	return sig
}

func tag(ns Namespace, nome string) string {
	if ns == PrefixoDS {
		return "ds:" + nome
	}
	return nome
}

// prefixoDeclarado diz se `prefixo` (ex.: "ds") já resolve em el ou em
// algum ancestral (xmlns:<prefixo>="...").
func prefixoDeclarado(el *etree.Element, prefixo string) bool {
	for el != nil {
		for _, a := range el.Attr {
			if a.Space == "xmlns" && a.Key == prefixo {
				return true
			}
		}
		el = el.Parent()
	}
	return false
}

// acharPorID acha, em profundidade, o primeiro elemento com atributo
// Id/id/ID igual a alvoID.
func acharPorID(el *etree.Element, alvoID string) *etree.Element {
	for _, a := range el.Attr {
		if (a.Key == "Id" || a.Key == "id" || a.Key == "ID") && a.Value == alvoID {
			return el
		}
	}
	for _, filho := range el.ChildElements() {
		if r := acharPorID(filho, alvoID); r != nil {
			return r
		}
	}
	return nil
}
