package assinador

// c14n_exclusiva_test.go — F7.3: PATCH APLICADO, testes revertidos pra prova positiva.
//
// Histórico (F7.2a/b, 08/11/2026): C14NExclusiva falhava em goxmldsig@v1.6.1 porque
// c14N10ExclusiveCanonicalizer.Canonicalize(el) nunca subia por el.Parent() pra resolver prefixo
// (nomeado OU padrão) declarado só num ANCESTRAL fora do elemento sendo canonicalizado — o
// canonicalizer INCLUSIVO já fazia isso (getParentNamespaceAndXmlAttributes/
// enhanceNamespaceAttributes). F7.2c confirmou: não é config (prefixList não resolve, testado);
// não há versão mais nova; é limitação relatada por terceiro desde 2022
// (github.com/russellhaering/goxmldsig issue #66), nunca corrigida. F7.2d avaliou patch local
// (replace no go.mod) vs. reimplementar C14N do zero — recomendou o patch.
//
// F7.3: o patch foi aplicado no fork github.com/javendisistemas-afk/goxmldsig (replace no
// go.mod) — dois arquivos, etreeutils/canonicalize.go (nova TransformExcC14nWithContext, que
// aceita um NSContext inicial) e canonicalize.go (c14N10ExclusiveCanonicalizer.Canonicalize passa
// a construir esse contexto com etreeutils.NSBuildParentContext(el), subindo os ancestrais reais,
// em vez de começar do zero). Testado de verdade (não só compilado): resolve os DOIS casos — a
// hipótese do F7.2d de que é a MESMA causa para prefixo nomeado e prefixo padrão se confirmou,
// sem divergência (PARE do F7.3 não foi acionado). Os 4 testes abaixo, que documentavam o bug,
// foram revertidos pra prova positiva — mesmos casos, resultado esperado invertido, com a MESMA
// rigor de sempre (digest/assinatura recomputados e verificados de verdade, não só "sem erro").

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

// TestAssinarC14NExclusiva_DigestEAssinaturaValidosDeVerdade — era
// TestAssinarC14NExclusiva_FalhaPorPrefixoHerdadoDoAncestral (F7.2a). O alvo ("rps1"/"rps2") usa
// prefixo (p1:) declarado só na raiz do documento, fora do elemento sendo assinado — exatamente o
// caso que o patch corrige. Prova real: digest recomputado E assinatura RSA verificada contra o
// certificado embutido (verificarTodasAsReferencias, que agora escolhe o canonicalizer pelo que o
// CanonicalizationMethod declara — F7.3), não só "Assinar não voltou erro".
func TestAssinarC14NExclusiva_DigestEAssinaturaValidosDeVerdade(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := lerArquivoTeste(t, "xml/lote-sem-assinatura-a.xml")

	saida, err := Assinar(entrada, []string{"rps1", "rps2", "lote1"}, chave, cert, PrefixoDS, C14NExclusiva)
	if err != nil {
		t.Fatalf("Assinar (C14NExclusiva, PrefixoDS): %v — F7.3 corrigiu este caso no fork; se "+
			"voltou a falhar, o patch regrediu ou o replace do go.mod não está apontando pro fork", err)
	}
	if !strings.Contains(string(saida), algC14NExclusiva) {
		t.Fatalf("saída não declara %q em nenhum CanonicalizationMethod/Transform", algC14NExclusiva)
	}

	resultados := verificarTodasAsReferencias(t, saida)
	if len(resultados) != 3 {
		t.Fatalf("esperava 3 assinaturas (rps1, rps2, lote1), achou %d", len(resultados))
	}
	for _, r := range resultados {
		if !r.valida() {
			t.Errorf("referência %q (C14NExclusiva, PrefixoDS): digestOk=%v assinaturaOk=%v — NÃO verificou",
				r.id, r.digestOk, r.assinaturaOk)
		}
	}
}

// TestAssinarC14NExclusivaPadraoNaSignature_DigestEAssinaturaValidosDeVerdade — era
// TestAssinarC14NExclusivaPadraoNaSignature_AlvoAindaFalhaPorAncestral (F7.2b). Mesmo caso do
// teste acima, com PadraoNaSignature (a variante que o DPS/ADN exige) — confirma que o patch
// resolve os dois modos do Signature igual, sem divergência.
func TestAssinarC14NExclusivaPadraoNaSignature_DigestEAssinaturaValidosDeVerdade(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := lerArquivoTeste(t, "xml/lote-sem-assinatura-a.xml")

	saida, err := Assinar(entrada, []string{"rps1", "rps2", "lote1"}, chave, cert, PadraoNaSignature, C14NExclusiva)
	if err != nil {
		t.Fatalf("Assinar (C14NExclusiva, PadraoNaSignature): %v — F7.3 corrigiu este caso no fork", err)
	}

	resultados := verificarTodasAsReferencias(t, saida)
	if len(resultados) != 3 {
		t.Fatalf("esperava 3 assinaturas (rps1, rps2, lote1), achou %d", len(resultados))
	}
	for _, r := range resultados {
		if !r.valida() {
			t.Errorf("referência %q (C14NExclusiva, PadraoNaSignature): digestOk=%v assinaturaOk=%v — NÃO verificou",
				r.id, r.digestOk, r.assinaturaOk)
		}
	}
}

// TestAssinarDocumentoC14NExclusiva_DigestEAssinaturaValidosDeVerdade — era
// TestAssinarDocumentoC14NExclusiva_FalhaNoSignedInfoNaoDeclarado (F7.2a), a falha mais grave das
// duas: mesmo assinando a RAIZ (onde p:/p1: estão corretamente declarados), o SignedInfo que o
// PRÓPRIO assinador monta herdava xmlns:ds do Signature que o envolve, nunca o redeclarando. Prova
// real, nos mesmos moldes de TestAssinarDocumento_DigestEAssinaturaValidosDeVerdade
// (assinar_documento_test.go): digest recomputado do XML original + assinatura RSA verificada com
// a chave pública — ambos com o canonicalizer EXCLUSIVO, não o inclusivo.
func TestAssinarDocumentoC14NExclusiva_DigestEAssinaturaValidosDeVerdade(t *testing.T) {
	testarAssinarDocumentoC14NExclusiva(t, PrefixoDS)
}

// TestAssinarDocumentoC14NExclusivaPadraoNaSignature_DigestEAssinaturaValidosDeVerdade — era
// TestAssinarDocumentoC14NExclusivaPadraoNaSignature_AssinaSemErroMasSignedInfoSemNamespace
// (F7.2b): a falha SILENCIOSA (sem erro, mas SignedInfo canonicalizado sem xmlns=xmldsig#) — a
// mais perigosa das quatro, porque não quebrava sozinha, só seria rejeitada por um verificador
// externo correto. Agora prova digest+assinatura válidos de verdade, E que a forma canônica do
// SignedInfo declara o namespace (inversão explícita do achado do F7.2b).
func TestAssinarDocumentoC14NExclusivaPadraoNaSignature_DigestEAssinaturaValidosDeVerdade(t *testing.T) {
	testarAssinarDocumentoC14NExclusiva(t, PadraoNaSignature)
}

func testarAssinarDocumentoC14NExclusiva(t *testing.T, ns Namespace) {
	chave, cert := carregarChaveECertificadoDeTeste(t)

	saida, err := AssinarDocumento([]byte(consultaSemAssinatura), chave, cert, ns, C14NExclusiva)
	if err != nil {
		t.Fatalf("AssinarDocumento (C14NExclusiva, ns=%v): %v — F7.3 corrigiu este caso no fork", ns, err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(saida); err != nil {
		t.Fatalf("saída não é XML válido: %v", err)
	}
	sig := doc.Root().SelectElement("Signature")
	if sig == nil {
		sig = doc.Root().SelectElement("ds:Signature")
	}
	if sig == nil {
		t.Fatal("não achei <Signature>/<ds:Signature> na saída")
	}
	signedInfo := sig.SelectElement("SignedInfo")
	if signedInfo == nil {
		signedInfo = sig.SelectElement("ds:SignedInfo")
	}
	if signedInfo == nil {
		t.Fatal("não achei SignedInfo dentro da Signature")
	}

	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// 1) digest da raiz bate com o C14N EXCLUSIVO do XML ORIGINAL (sem Signature nenhuma) —
	// prova que o digest foi calculado antes da Signature existir, com o algoritmo certo.
	docOriginal := etree.NewDocument()
	if err := docOriginal.ReadFromBytes([]byte(consultaSemAssinatura)); err != nil {
		t.Fatalf("reparse do original: %v", err)
	}
	c14nOriginal, err := canon.Canonicalize(docOriginal.Root())
	if err != nil {
		t.Fatalf("C14N exclusivo do original: %v", err)
	}
	digestEsperadoArr := sha1.Sum(c14nOriginal)
	digestEsperado := digestEsperadoArr[:]
	digestValueEl := signedInfo.FindElement("Reference/DigestValue")
	if digestValueEl == nil {
		digestValueEl = signedInfo.FindElement("ds:Reference/ds:DigestValue")
	}
	if digestValueEl == nil {
		t.Fatal("não achei DigestValue")
	}
	digestObtido, err := base64.StdEncoding.DecodeString(digestValueEl.Text())
	if err != nil {
		t.Fatalf("DigestValue não é base64 válido: %v", err)
	}
	if string(digestObtido) != string(digestEsperado) {
		t.Fatalf("🔴 DigestValue não bate com o C14N exclusivo do XML original — a assinatura cobriria "+
			"o conteúdo ERRADO.\n  esperado: %x\n  obtido:   %x", digestEsperado, digestObtido)
	}

	// 2) releitura FRESCA (não a árvore viva que AssinarDocumento usou) pra recanonicalizar o
	// SignedInfo exatamente como um verificador externo faria — e confirmar que ele DECLARA
	// xmlns=xmldsig# quando herdado de um Signature sem prefixo (inversão do achado F7.2b).
	if ns == PadraoNaSignature {
		canonSignedInfo, err := canon.Canonicalize(signedInfo.Copy())
		if err != nil {
			t.Fatalf("C14N exclusivo do SignedInfo: %v", err)
		}
		if !strings.Contains(string(canonSignedInfo), `xmlns="`+nsXMLDSig+`"`) {
			t.Fatalf("🔴 forma canônica do SignedInfo ainda NÃO declara xmlns=%s — o patch não resolveu "+
				"o caso do namespace padrão. canônico: %s", nsXMLDSig, canonSignedInfo)
		}
	}

	// 3) a ASSINATURA RSA É VÁLIDA DE VERDADE — verifica com a chave PÚBLICA do certificado,
	// contra o C14N exclusivo do SignedInfo tal como está no documento assinado.
	signedInfoC14n, err := canon.Canonicalize(signedInfo)
	if err != nil {
		t.Fatalf("C14N exclusivo do SignedInfo assinado: %v", err)
	}
	hashSignedInfoArr := sha1.Sum(signedInfoC14n)
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
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashSignedInfoArr[:], assinaturaBytes); err != nil {
		t.Fatalf("🔴 VERIFICAÇÃO RSA FALHOU: %v — a assinatura embutida NÃO é válida para o SignedInfo "+
			"presente no documento", err)
	}
}

// TestAssinarC14NInclusiva_SaidaIdenticaAoComportamentoDeAntes é o controle: com C14NInclusiva
// (valor que TODO caller de produção passa hoje), a saída tem de continuar byte a byte igual ao
// golden pré-F7.2a — nem o parâmetro C14N (F7.2a) nem o patch do fork (F7.3, que só toca o
// caminho EXCLUSIVO) podem ter mudado o caminho antigo, nem por acidente.
func TestAssinarC14NInclusiva_SaidaIdenticaAoComportamentoDeAntes(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := lerArquivoTeste(t, "xml/lote-sem-assinatura-a.xml")
	esperado := lerArquivoTeste(t, "xml/lote-assinado-a.xml")

	saida, err := Assinar(entrada, []string{"rps1", "rps2", "lote1"}, chave, cert, PrefixoDS, C14NInclusiva)
	if err != nil {
		t.Fatalf("Assinar (C14NInclusiva): %v", err)
	}
	if string(saida) != string(esperado) {
		t.Fatalf("C14NInclusiva mudou a saída em relação ao golden pré-F7.2a — nenhuma das duas fatias deveria afetar este caminho")
	}
}
