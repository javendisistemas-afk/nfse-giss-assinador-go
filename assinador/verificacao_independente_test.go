package assinador

// verificacao_independente_test.go — achado da investigação do E174/RPS 298 (SEGURANÇA,
// 02/11/2026): "ligar o XML real do enfileirador à assinatura" com uma prova que não confie em
// si mesma. TestAssinarReproduzOsVetoresDourados (assinador_test.go) já prova que ESTE pacote
// reproduz um golden byte a byte — mas isso é bytes-contra-bytes, não matemática. Aqui a
// verificação recomputa o digest de cada Reference (C14N inclusivo, sha1) e confere a
// SignatureValue (RSA-SHA1) contra o certificado embutido na própria Signature, sem chamar
// Assinar nem nada que dependa dele — é um caminho de código SEPARADO, equivalente ao que um
// verificador externo (GISS, xmlsec1) faria.
//
// Roda contra testdata/formato_giss/* — os 6 XML golden gerados pelo WRITER REAL do backend
// (backend/nfse_rps_xml.go, fatia F3.4), não um fixture inventado — e contra
// testdata/negativos/{n1,n2,n3}, cujo golden.json já diz qual referência deve reprovar em cada
// um: sem o controle negativo, "aceita o documento bom" não prova que o verificador REPROVA o
// documento ruim (a mesma régua de "busca vazia só vale com controle" do CLAUDE.md, aplicada a
// um verificador em vez de uma busca).
import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type resultadoRef struct {
	id           string
	digestOk     bool
	assinaturaOk bool
}

func (r resultadoRef) valida() bool { return r.digestOk && r.assinaturaOk }

// canonicalizadorDoAlgoritmo devolve o Canonicalizer que corresponde à URI que
// CanonicalizationMethod/Algorithm declara — mesma correspondência que algC14NDe/canonicalizadorDe
// usam pra ASSINAR (assinador.go), aqui do lado de VERIFICAR.
func canonicalizadorDoAlgoritmo(alg string) (dsig.Canonicalizer, bool) {
	switch alg {
	case algC14NInclusiva:
		return dsig.MakeC14N10RecCanonicalizer(), true
	case algC14NExclusiva:
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), true
	default:
		return nil, false
	}
}

// verificarTodasAsReferencias acha toda <ds:Signature> (ou <Signature xmlns=.../>, variante B)
// no documento e, pra cada uma, recomputa o digest do elemento que a Reference aponta (pelo
// Id) e confere a SignatureValue contra o X509Certificate embutido na própria Signature —
// nunca contra um certificado externo, e nunca usando `Assinar`/`acharPorID` como ORIGEM da
// verdade (usa `acharPorID` só pra achar o elemento, que é busca, não verificação).
func verificarTodasAsReferencias(t *testing.T, xmlBytes []byte) []resultadoRef {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("parseando XML: %v", err)
	}

	var assinaturas []*etree.Element
	var percorrer func(el *etree.Element)
	percorrer = func(el *etree.Element) {
		for _, c := range el.ChildElements() {
			if c.Tag == "Signature" {
				assinaturas = append(assinaturas, c)
			}
			percorrer(c)
		}
	}
	percorrer(doc.Root())

	resultados := make([]resultadoRef, 0, len(assinaturas))

	for _, sig := range assinaturas {
		signedInfo := sig.SelectElement("SignedInfo")
		if signedInfo == nil {
			t.Fatalf("Signature sem SignedInfo")
		}

		// F7.3: usa o MESMO canonicalizer que o CanonicalizationMethod declara, em vez de
		// assumir sempre o inclusivo — um verificador externo real faz exatamente isso (lê o
		// Algorithm declarado, não assume). Sem isto, uma assinatura feita com C14NExclusiva
		// seria recanonicalizada errado aqui e pareceria inválida mesmo estando correta.
		metodoC14N := signedInfo.FindElement("CanonicalizationMethod")
		if metodoC14N == nil {
			t.Fatalf("SignedInfo sem CanonicalizationMethod")
		}
		canon, ok := canonicalizadorDoAlgoritmo(metodoC14N.SelectAttrValue("Algorithm", ""))
		if !ok {
			t.Fatalf("CanonicalizationMethod/Algorithm desconhecido: %q", metodoC14N.SelectAttrValue("Algorithm", ""))
		}
		refEl := signedInfo.SelectElement("Reference")
		if refEl == nil {
			t.Fatalf("SignedInfo sem Reference")
		}
		uri := refEl.SelectAttrValue("URI", "")
		if len(uri) < 2 || uri[0] != '#' {
			t.Fatalf("Reference URI inesperada: %q", uri)
		}
		id := uri[1:]
		r := resultadoRef{id: id}

		digestEl := refEl.SelectElement("DigestValue")
		digestEsperado, err := base64.StdEncoding.DecodeString(digestEl.Text())
		if err != nil {
			t.Fatalf("DigestValue base64 inválido (%s): %v", id, err)
		}

		if alvo := acharPorID(doc.Root(), id); alvo != nil {
			if canonicoAlvo, err := canon.Canonicalize(alvo); err == nil {
				digestCalculado := sha1.Sum(canonicoAlvo)
				r.digestOk = string(digestCalculado[:]) == string(digestEsperado)
			}
		}

		if certEl := sig.FindElement("KeyInfo/X509Data/X509Certificate"); certEl != nil {
			if certDER, err := base64.StdEncoding.DecodeString(certEl.Text()); err == nil {
				if cert, err := x509.ParseCertificate(certDER); err == nil {
					if canonicoSignedInfo, err := canon.Canonicalize(signedInfo); err == nil {
						if sigValueEl := sig.SelectElement("SignatureValue"); sigValueEl != nil {
							if sigBytes, err := base64.StdEncoding.DecodeString(sigValueEl.Text()); err == nil {
								r.assinaturaOk = cert.CheckSignature(x509.SHA1WithRSA, canonicoSignedInfo, sigBytes) == nil
							}
						}
					}
				}
			}
		}

		resultados = append(resultados, r)
	}
	return resultados
}

// TestVerificacaoIndependenteAceitaFormatoGISSReal assina os 6 XML REAIS do gerador do backend
// (mesmos de TestAssinarFormatoGISSReal, variante PrefixoDS — a usada em produção,
// nfse_enfileirar.go) e verifica, de forma independente, que TODA referência produzida
// verifica — digest E assinatura, não só "o Assinar não devolveu erro".
func TestVerificacaoIndependenteAceitaFormatoGISSReal(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	for _, c := range casosFormatoGISS {
		t.Run(c.arquivo, func(t *testing.T) {
			entrada := lerArquivoTeste(t, c.arquivo)
			saida, err := Assinar(entrada, c.alvos, chave, cert, PrefixoDS, C14NInclusiva)
			if err != nil {
				t.Fatalf("Assinar: %v", err)
			}
			resultados := verificarTodasAsReferencias(t, saida)
			if len(resultados) != len(c.alvos) {
				t.Fatalf("esperava %d assinatura(s), achou %d", len(c.alvos), len(resultados))
			}
			for _, r := range resultados {
				if !r.digestOk {
					t.Errorf("referência %q: digest recomputado NÃO bate com o DigestValue do XML assinado", r.id)
				}
				if !r.assinaturaOk {
					t.Errorf("referência %q: SignatureValue NÃO verifica contra o certificado embutido", r.id)
				}
			}
		})
	}
}

// TestVerificacaoIndependenteAceitaVetoresDourados roda a mesma verificação contra o golden do
// VENDOR (testdata/xml/lote-assinado-a.xml), já aprovado por xmlsec1 segundo testdata/README.md
// — cross-check de que esta verificação concorda com uma ferramenta externa, não só com este
// pacote.
func TestVerificacaoIndependenteAceitaVetoresDourados(t *testing.T) {
	saida := lerArquivoTeste(t, "xml/lote-assinado-a.xml")
	resultados := verificarTodasAsReferencias(t, saida)
	if len(resultados) != 3 {
		t.Fatalf("esperava 3 assinaturas (rps1, rps2, lote1), achou %d", len(resultados))
	}
	for _, r := range resultados {
		if !r.valida() {
			t.Errorf("referência %q do golden do vendor (xmlsec1-aprovado) NÃO verificou: digestOk=%v assinaturaOk=%v",
				r.id, r.digestOk, r.assinaturaOk)
		}
	}
}

// TestVerificacaoIndependenteReprovaNegativos — controle: sem isto, "aceita o bom" não prova
// que o verificador REPROVA o ruim. golden.json diz, por arquivo, qual referência deve dar
// inválida; os 3 negativos cobrem 3 formas diferentes de adulteração (texto do RPS, número do
// lote, DigestValue trocado).
func TestVerificacaoIndependenteReprovaNegativos(t *testing.T) {
	var g struct {
		Negativos []struct {
			Arquivo            string          `json:"arquivo"`
			ReferenciasValidas map[string]bool `json:"referencias_validas"`
		} `json:"negativos"`
	}
	if err := json.Unmarshal(lerArquivoTeste(t, "golden.json"), &g); err != nil {
		t.Fatalf("lendo golden.json: %v", err)
	}
	if len(g.Negativos) == 0 {
		t.Fatal("golden.json sem seção 'negativos' — fixture mudou? este teste depende dela")
	}

	for _, neg := range g.Negativos {
		t.Run(neg.Arquivo, func(t *testing.T) {
			xmlBytes := lerArquivoTeste(t, neg.Arquivo)
			resultados := verificarTodasAsReferencias(t, xmlBytes)
			achadas := make(map[string]resultadoRef, len(resultados))
			for _, r := range resultados {
				achadas[r.id] = r
			}
			for id, esperadoValida := range neg.ReferenciasValidas {
				r, ok := achadas[id]
				if !ok {
					t.Fatalf("referência %q (golden.json) não encontrada no documento", id)
				}
				if r.valida() != esperadoValida {
					t.Errorf("referência %q: golden.json diz válida=%v, verificação independente deu válida=%v (digestOk=%v assinaturaOk=%v)",
						id, esperadoValida, r.valida(), r.digestOk, r.assinaturaOk)
				}
			}
		})
	}
}
