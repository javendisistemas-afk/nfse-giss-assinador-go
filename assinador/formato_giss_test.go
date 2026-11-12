package assinador

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pastaSaidaGISS — se setada (variável de ambiente), TestAssinarFormatoGISSReal
// escreve ali o XML assinado de cada golden (uma subpasta por variante), para
// verificação INDEPENDENTE (fora do Go/goxmldsig) fora deste pacote. Vazio =
// não escreve nada (é o caso do `go test` normal, sem efeito colateral em disco).
const envPastaSaidaGISS = "ASSINADOR_SAIDA_GISS_DIR"

var casosFormatoGISS = []struct {
	arquivo string
	alvos   []string
}{
	{"formato_giss/gerar_nfse_1rps.xml", []string{"rps_1_1006"}},
	{"formato_giss/lote_1rps_completo.xml", []string{"rps_1_1001", "lote_1"}},
	{"formato_giss/lote_1rps_especiais.xml", []string{"rps_1_1008", "lote_6"}},
	{"formato_giss/lote_1rps_limites.xml", []string{"rps_1_1007", "lote_5"}},
	{"formato_giss/lote_1rps_sem_ibscbs.xml", []string{"rps_1_1005", "lote_4"}},
	{"formato_giss/lote_2rps.xml", []string{"rps_1_1003", "rps_1_1004", "lote_3"}},
}

// TestAssinarFormatoGISSReal assina os 6 XML golden REAIS do gerador de
// referência (backend/nfse_rps_xml.go, fatia F3.4 — não os vetores do
// vetores-fiscal-agent.zip), nas DUAS variantes de namespace. O root desses
// golden não declara xmlns:ds nem xmlns:xsi (medido lendo
// backend/nfse_rps_xml_escrita.go: "regra 2: a raiz não declara mais nada").
//
// Achado da F4.2b: a verificação INDEPENDENTE (lxml c14n + openssl, fora
// deste repo) bate 100% para PrefixoDS nos 6 arquivos — é a variante
// recomendada para a saída real do gerador, por nunca introduzir xmlns
// padrão (nenhuma ambiguidade possível). Para PadraoNaSignature, a MESMA
// verificação lxml diverge — mas o MESMO script, rodado contra o golden do
// VENDOR (testdata/xml/lote-assinado-b.xml, já validado por xmlsec1 segundo
// o README dos vetores), diverge DA MESMA FORMA: é um bug do lxml (C14N de
// namespace padrão além de 1 nível de profundidade), não do goxmldsig nem
// deste assinador — mas fica sem prova independente própria nesta fatia.
func TestAssinarFormatoGISSReal(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	pastaSaida := os.Getenv(envPastaSaidaGISS)

	for _, ns := range []struct {
		nome  string
		valor Namespace
	}{
		{"PrefixoDS", PrefixoDS},
		{"PadraoNaSignature", PadraoNaSignature},
	} {
		t.Run(ns.nome, func(t *testing.T) {
			for _, c := range casosFormatoGISS {
				t.Run(c.arquivo, func(t *testing.T) {
					entrada := lerArquivoTeste(t, c.arquivo)

					saida, err := Assinar(entrada, c.alvos, chave, cert, ns.valor, C14NInclusiva)
					if err != nil {
						t.Fatalf("Assinar (%s): %v", ns.nome, err)
					}

					if pastaSaida != "" {
						destinoDir := filepath.Join(pastaSaida, ns.nome)
						if err := os.MkdirAll(destinoDir, 0o755); err != nil {
							t.Fatalf("criando %s: %v", destinoDir, err)
						}
						destino := filepath.Join(destinoDir, filepath.Base(c.arquivo))
						if err := os.WriteFile(destino, saida, 0o644); err != nil {
							t.Fatalf("escrevendo saída em %s: %v", destino, err)
						}
						t.Logf("saída assinada escrita em %s (%d bytes)", destino, len(saida))
					}
				})
			}
		})
	}
}

// TestAssinarFormatoGISSReal_PrefixoDSAutoDeclaraXmlnsDs documenta e prova a
// lacuna achada NESTA fatia (F4.2b): o gerador de referência não declara
// xmlns:ds na raiz (só xmlns:p/xmlns:p1). Sem correção, pedir a variante
// PrefixoDS contra essa saída real não dava erro nenhum — o C14N10Rec do
// goxmldsig não valida prefixo não declarado, e o XML final saía com "ds:"
// usado sem NENHUMA declaração em lugar nenhum do documento (malformado
// quanto a namespaces, silenciosamente). O conserto: Assinar agora detecta
// a ausência e declara xmlns:ds na própria Signature (mesma solução que
// PadraoNaSignature já usa, só que com prefixo em vez de xmlns padrão).
func TestAssinarFormatoGISSReal_PrefixoDSAutoDeclaraXmlnsDs(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := lerArquivoTeste(t, "formato_giss/gerar_nfse_1rps.xml")

	saida, err := Assinar(entrada, []string{"rps_1_1006"}, chave, cert, PrefixoDS, C14NInclusiva)
	if err != nil {
		t.Fatalf("Assinar (PrefixoDS, raiz sem xmlns:ds): %v", err)
	}
	if !strings.Contains(string(saida), `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`) {
		t.Fatalf("saída usa ds: mas não declara xmlns:ds em lugar nenhum — malformado quanto a namespaces:\n%s", saida)
	}
}

// TestAssinarReproduzOsVetoresDourados_A_NaoGanhaXmlnsDsDuplicado é o
// controle do conserto acima: os vetores da F4.2 (variante A) JÁ declaram
// xmlns:ds na raiz — o auto-declare não pode acrescentar um SEGUNDO
// xmlns:ds na Signature, senão o golden byte a byte da F4.2 quebraria.
func TestAssinarReproduzOsVetoresDourados_A_NaoGanhaXmlnsDsDuplicado(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := lerArquivoTeste(t, "xml/lote-sem-assinatura-a.xml")

	saida, err := Assinar(entrada, []string{"rps1", "rps2", "lote1"}, chave, cert, PrefixoDS, C14NInclusiva)
	if err != nil {
		t.Fatalf("Assinar: %v", err)
	}
	n := strings.Count(string(saida), "xmlns:ds=")
	if n != 1 {
		t.Fatalf("esperava xmlns:ds declarado exatamente 1 vez (na raiz, como já vinha), achou %d", n)
	}
}
