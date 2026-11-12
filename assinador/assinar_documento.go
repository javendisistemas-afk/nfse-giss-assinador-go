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
)

// AssinarDocumento assina a RAIZ do documento inteiro — toda ela, Signature incluída como seu
// próprio último filho — usando Reference com URI="" (mesmo documento), em vez do URI="#id" que
// Assinar usa.
//
// 🔑 POR QUE UMA FUNÇÃO SEPARADA, NÃO Assinar COM OUTRO PARÂMETRO (F4.37, 21/10/2026): Assinar
// acha o alvo por atributo Id e recusa explicitamente se o alvo for a raiz do documento ("não pode
// receber Signature irmã" — a Signature entraria como filha do PAI do alvo, e a raiz não tem pai).
// Isso nunca foi problema pro RecepcionarLoteRps (o alvo, LoteRps/InfDeclaracaoPrestacaoServico,
// nunca é a raiz — está dentro de EnviarLoteRpsEnvio). Mas pro ConsultarLoteRps, o suporte da GISS
// confirmou que exige assinatura, e o XSD local
// (consultar-lote-rps-envio-v2_04.xsd) mostra que ConsultarLoteRpsEnvio não declara NENHUM
// atributo — nem Id, nem xsd:anyAttribute: Prestador + Protocolo + Signature(opcional), só isso.
// Não tem onde pendurar um Id, e inventar um que o XSD não prevê arriscaria rejeição por schema
// inválido — um problema novo, não o que estamos tentando resolver. A saída padrão do XML-DSig pra
// "assine o documento inteiro, sem Id nenhum" é exatamente Reference URI="" (same-document
// reference) — e é isso que esta função faz: a Signature é filha da PRÓPRIA raiz (enveloped
// signature clássico), e o digest da raiz é calculado ANTES de ela existir (mesma ordem de
// Assinar), então o transform enveloped-signature (já usado em todo alvo) exclui a Signature de si
// mesma sem precisar de nada especial.
func AssinarDocumento(xmlEntrada []byte, chave *rsa.PrivateKey, certificado *x509.Certificate, ns Namespace, c14n C14N) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlEntrada); err != nil {
		return nil, fmt.Errorf("assinador: XML de entrada inválido: %w", err)
	}
	raiz := doc.Root()
	if raiz == nil {
		return nil, fmt.Errorf("assinador: XML de entrada sem elemento raiz")
	}
	if err := verificarConstrucaoSuportada(raiz); err != nil {
		return nil, fmt.Errorf("assinador: raiz: %w", err)
	}

	canon := canonicalizadorDe(c14n)
	certB64 := base64.StdEncoding.EncodeToString(certificado.Raw)

	// 1) digest da raiz, no estado ATUAL — sem nenhuma Signature ainda, porque é o único alvo e
	// ela ainda nem foi criada (passo 2).
	raizC14n, err := canon.Canonicalize(raiz)
	if err != nil {
		return nil, fmt.Errorf("assinador: C14N da raiz: %w", err)
	}
	digestRaiz := sha1.Sum(raizC14n)

	// 2) monta o esqueleto do Signature e anexa como ÚLTIMO FILHO da PRÓPRIA raiz (não de um pai
	// — a raiz não tem pai). Mesma ordem de assinarUmNo: anexa ANTES de preencher os valores, pro
	// C14N do SignedInfo (passo 3) herdar o contexto de namespace correto dos ancestrais reais.
	sig := montarEsqueleto(ns, c14n)
	if ns == PrefixoDS && !prefixoDeclarado(raiz, "ds") {
		sig.CreateAttr("xmlns:ds", nsXMLDSig)
	}
	raiz.AddChild(sig)

	signedInfo := sig.SelectElement(tag(ns, "SignedInfo"))
	referencia := signedInfo.SelectElement(tag(ns, "Reference"))
	referencia.CreateAttr("URI", "")
	referencia.SelectElement(tag(ns, "DigestValue")).SetText(base64.StdEncoding.EncodeToString(digestRaiz[:]))

	// 3) assina o SignedInfo já anexado ao documento.
	signedInfoC14n, err := canon.Canonicalize(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("assinador: C14N do SignedInfo (raiz): %w", err)
	}
	hashSignedInfo := sha1.Sum(signedInfoC14n)
	assinatura, err := rsa.SignPKCS1v15(rand.Reader, chave, crypto.SHA1, hashSignedInfo[:])
	if err != nil {
		return nil, fmt.Errorf("assinador: assinatura RSA-SHA1 (raiz): %w", err)
	}
	sig.SelectElement(tag(ns, "SignatureValue")).SetText(base64.StdEncoding.EncodeToString(assinatura))

	x509CertEl := sig.FindElement(tag(ns, "KeyInfo") + "/" + tag(ns, "X509Data") + "/" + tag(ns, "X509Certificate"))
	x509CertEl.SetText(certB64)

	saida, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("assinador: falha ao serializar XML assinado: %w", err)
	}
	return saida, nil
}
