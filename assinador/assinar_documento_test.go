package assinador

// assinar_documento_test.go — F4.37: ConsultarLoteRpsEnvio não tem (nem pode ter, por XSD)
// atributo Id, então AssinarDocumento assina a raiz via Reference URI="" em vez de "#id". Em vez
// de um golden byte-a-byte (que só prova "saiu igual a uma vez que rodei e aceitei"), este teste
// VERIFICA de forma independente: recomputa o digest da raiz a partir do XML ORIGINAL (não do
// assinado) e confere contra o DigestValue embutido; e verifica a assinatura RSA com a CHAVE
// PÚBLICA do certificado de teste (crypto/rsa.VerifyPKCS1v15) — prova criptográfica real, não só
// "tem um <Signature> lá".

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Dado FICTÍCIO (achado SEGURANÇA, revisão do poller F5.4): até o commit 2612f86 este fixture
// trazia CNPJ/IM/protocolo REAIS, fora do padrão fictício já estabelecido em testdata/README.md.
// CNPJ aqui é o mesmo fictício do certificado de teste (CN "EMPRESA TESTE LTDA:11222333000181");
// IM e protocolo são placeholders óbvios. O teste não depende do VALOR de nenhum destes campos —
// só do mecanismo genérico de assinatura (digest/verificação RSA sobre o que estiver no XML).
const consultaSemAssinatura = `<?xml version="1.0" encoding="UTF-8"?><p:ConsultarLoteRpsEnvio xmlns:p="http://www.giss.com.br/consultar-lote-rps-envio-v2_04.xsd" xmlns:p1="http://www.giss.com.br/tipos-v2_04.xsd"><p:Prestador><p1:CpfCnpj><p1:Cnpj>11222333000181</p1:Cnpj></p1:CpfCnpj><p1:InscricaoMunicipal>00000</p1:InscricaoMunicipal></p:Prestador><p:Protocolo>9999999</p:Protocolo></p:ConsultarLoteRpsEnvio>`

// TestAssinarDocumento_DigestEAssinaturaValidosDeVerdade — a prova central: recomputa o digest a
// partir do XML original (sem olhar o que AssinarDocumento gravou) e verifica a assinatura RSA com
// a chave pública. Se qualquer passo (ordem do digest, conteúdo canonicalizado, SignedInfo
// assinado) estivesse errado, a verificação FALHARIA — não é checagem de presença/estrutura.
func TestAssinarDocumento_DigestEAssinaturaValidosDeVerdade(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)

	saida, err := AssinarDocumento([]byte(consultaSemAssinatura), chave, cert, PrefixoDS, C14NInclusiva)
	if err != nil {
		t.Fatalf("AssinarDocumento: %v", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(saida); err != nil {
		t.Fatalf("saída não é XML válido: %v", err)
	}

	// 1) exatamente UMA ds:Signature, como ÚLTIMO filho da raiz.
	sigs := doc.Root().SelectElements("Signature")
	if len(sigs) == 0 {
		sigs = doc.Root().SelectElements("ds:Signature")
	}
	if len(sigs) != 1 {
		t.Fatalf("achei %d <Signature>/<ds:Signature>, esperava exatamente 1", len(sigs))
	}
	sig := sigs[0]
	filhos := doc.Root().ChildElements()
	if filhos[len(filhos)-1] != sig {
		t.Fatal("🔴 a Signature não é o ÚLTIMO filho da raiz — enveloped signature fora do padrão esperado")
	}

	// 2) Reference URI="" — ConsultarLoteRpsEnvio não tem atributo Id, então tem de ser
	// same-document reference, nunca "#algumId".
	referencia := sig.FindElement("SignedInfo/Reference")
	if referencia == nil {
		referencia = sig.FindElement("ds:SignedInfo/ds:Reference")
	}
	if referencia == nil {
		t.Fatal("não achei SignedInfo/Reference")
	}
	if uri := referencia.SelectAttrValue("URI", "<ausente>"); uri != "" {
		t.Fatalf("Reference URI=%q, esperava \"\" (same-document, sem Id)", uri)
	}

	// 3) DigestValue bate com o C14N do XML ORIGINAL (sem assinatura nenhuma) — prova que o
	// digest foi calculado ANTES de qualquer Signature existir, não depois (o que incluiria a
	// própria Signature no hash e invalidaria a verificação na GISS).
	docOriginal := etree.NewDocument()
	if err := docOriginal.ReadFromBytes([]byte(consultaSemAssinatura)); err != nil {
		t.Fatalf("reparse do original: %v", err)
	}
	canon := dsig.MakeC14N10RecCanonicalizer()
	c14nOriginal, err := canon.Canonicalize(docOriginal.Root())
	if err != nil {
		t.Fatalf("C14N do original: %v", err)
	}
	digestEsperado := sha1.Sum(c14nOriginal)
	digestValueEl := referencia.FindElement("DigestMethod/../DigestValue")
	if digestValueEl == nil {
		digestValueEl = sig.FindElement("SignedInfo/Reference/DigestValue")
	}
	if digestValueEl == nil {
		t.Fatal("não achei DigestValue")
	}
	digestObtido, err := base64.StdEncoding.DecodeString(digestValueEl.Text())
	if err != nil {
		t.Fatalf("DigestValue não é base64 válido: %v", err)
	}
	if string(digestObtido) != string(digestEsperado[:]) {
		t.Fatalf("🔴 DigestValue não bate com o C14N do XML original — a assinatura cobriria o "+
			"conteúdo ERRADO.\n  esperado (hex via %%x): %x\n  obtido:                %x", digestEsperado, digestObtido)
	}

	// 4) A ASSINATURA RSA É VÁLIDA DE VERDADE — verifica com a chave PÚBLICA do certificado,
	// contra o C14N do SignedInfo tal como ele está no documento assinado (não recomputado do
	// zero): prova que SignatureValue é realmente a assinatura RSA-SHA1 de SignedInfo, não um
	// valor qualquer.
	signedInfoEl := sig.SelectElement("SignedInfo")
	if signedInfoEl == nil {
		signedInfoEl = sig.SelectElement("ds:SignedInfo")
	}
	signedInfoC14n, err := canon.Canonicalize(signedInfoEl)
	if err != nil {
		t.Fatalf("C14N do SignedInfo assinado: %v", err)
	}
	hashSignedInfo := sha1.Sum(signedInfoC14n)
	sigValueEl := sig.FindElement("SignatureValue")
	if sigValueEl == nil {
		sigValueEl = sig.FindElement("ds:SignatureValue")
	}
	assinaturaBytes, err := base64.StdEncoding.DecodeString(sigValueEl.Text())
	if err != nil {
		t.Fatalf("SignatureValue não é base64 válido: %v", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("chave pública do certificado de teste não é RSA: %T", cert.PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashSignedInfo[:], assinaturaBytes); err != nil {
		t.Fatalf("🔴 VERIFICAÇÃO RSA FALHOU: %v — a assinatura embutida NÃO é válida para o "+
			"SignedInfo presente no documento", err)
	}

	// 5) controle: o X509Certificate embutido é o mesmo certificado de teste usado pra assinar
	// (sem isto, os itens 1-4 passariam mesmo com um certificado trocado por engano).
	x509El := sig.FindElement("KeyInfo/X509Data/X509Certificate")
	if x509El == nil {
		x509El = sig.FindElement("ds:KeyInfo/ds:X509Data/ds:X509Certificate")
	}
	certEmbutido, err := base64.StdEncoding.DecodeString(x509El.Text())
	if err != nil {
		t.Fatalf("X509Certificate não é base64 válido: %v", err)
	}
	if string(certEmbutido) != string(cert.Raw) {
		t.Fatal("🔴 X509Certificate embutido não é o certificado de teste esperado")
	}
}

// TestAssinarDocumento_RaizSemFilhosAindaAssina — caso degenerado: mesmo sem Prestador/Protocolo
// de verdade, qualquer elemento raiz pode ser assinado — AssinarDocumento não depende da
// ESTRUTURA do ConsultarLoteRpsEnvio especificamente, só de ter uma raiz.
func TestAssinarDocumento_RaizSemFilhosAindaAssina(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := `<?xml version="1.0"?><raiz xmlns="urn:teste"></raiz>`
	saida, err := AssinarDocumento([]byte(entrada), chave, cert, PadraoNaSignature, C14NInclusiva)
	if err != nil {
		t.Fatalf("AssinarDocumento: %v", err)
	}
	if !strings.Contains(string(saida), "<Signature") {
		t.Fatalf("saída não contém <Signature>: %s", saida)
	}
}

// TestAssinarDocumento_XMLInvalidoFalha — guarda de erro, como TestAssinarIdInexistenteFalha faz
// pra Assinar.
func TestAssinarDocumento_XMLInvalidoFalha(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	_, err := AssinarDocumento([]byte("isto não é XML"), chave, cert, PrefixoDS, C14NInclusiva)
	if err == nil {
		t.Fatal("🔴 XML inválido passou sem erro")
	}
}
