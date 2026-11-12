package transmissor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMontarEnvelopeGerarNfse_WrapperEhGerarNfseRequest ancora o nome do
// elemento-wrapper FORNECIDO PELO PO (schema de nfse.wsdl colado na
// conversa): <xs:element name="GerarNfseRequest" type="tns:input"/>, global
// no namespace http://nfse.abrasf.org.br — não "GerarNfse" (palpite inicial
// da Parte A, sem rede).
func TestMontarEnvelopeGerarNfse_WrapperEhGerarNfseRequest(t *testing.T) {
	envelope, err := MontarEnvelopeGerarNfse([]byte(`<a/>`), "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeGerarNfse: %v", err)
	}
	if !strings.Contains(string(envelope), ":GerarNfseRequest") {
		t.Fatalf("envelope não contém o wrapper GerarNfseRequest:\n%s", envelope)
	}
	if strings.Contains(string(envelope), ":GerarNfse>") {
		t.Fatalf("envelope ainda usa o wrapper antigo GerarNfse (sem Request):\n%s", envelope)
	}
}

// TestMontarEnvelopeGerarNfse_RoundTripByteIdentico é a prova central do
// item (d): o XML extraído de volta do envelope (nfseDadosMsg, des-escapado)
// tem de ser BYTE-IDÊNTICO ao XML assinado que entrou.
func TestMontarEnvelopeGerarNfse_RoundTripByteIdentico(t *testing.T) {
	// reaproveita um golden já assinado e verificado nas fatias F4.2/F4.2b —
	// não depende de rede nem de certificado real.
	caminho := filepath.Join("..", "testdata", "xml", "lote-assinado-a.xml")
	xmlAssinado, err := os.ReadFile(caminho)
	if err != nil {
		t.Fatalf("lendo %s: %v", caminho, err)
	}

	envelope, err := MontarEnvelopeGerarNfse(xmlAssinado, "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeGerarNfse: %v", err)
	}

	extraido, err := extrairTextoDeElemento(envelope, "nfseDadosMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento(nfseDadosMsg): %v", err)
	}

	if string(extraido) != string(xmlAssinado) {
		t.Fatalf("round-trip não bate: extraído (%d bytes) != assinado (%d bytes)", len(extraido), len(xmlAssinado))
	}
}

// TestMontarEnvelopeGerarNfse_CabecalhoRoundTrip confere o mesmo para o
// nfseCabecMsg: o cabeçalho extraído bate com o que foi montado.
func TestMontarEnvelopeGerarNfse_CabecalhoRoundTrip(t *testing.T) {
	envelope, err := MontarEnvelopeGerarNfse([]byte(`<a/>`), "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeGerarNfse: %v", err)
	}

	extraido, err := extrairTextoDeElemento(envelope, "nfseCabecMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento(nfseCabecMsg): %v", err)
	}

	esperado := montarCabecalho("2.04")
	if string(extraido) != string(esperado) {
		t.Fatalf("cabeçalho não bate:\n  esperado=%s\n  extraido=%s", esperado, extraido)
	}
}

// TestMontarEnvelopeGerarNfse_EscapaCaracteresEspeciais prova que o
// round-trip sobrevive a '<', '>', '&' e aspas no meio do XML assinado
// (o caso real: Discriminacao com "&amp;"/"&lt;"/"&gt;" já escapados PELO
// GERADOR, que agora vão ser escapados de NOVO ao entrar no envelope).
func TestMontarEnvelopeGerarNfse_EscapaCaracteresEspeciais(t *testing.T) {
	xmlComEspeciais := []byte(`<a attr="x&amp;y">GENERICA &amp; CIA &lt;TESTE&gt; "aspas" 'apostrofo'</a>`)

	envelope, err := MontarEnvelopeGerarNfse(xmlComEspeciais, "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeGerarNfse: %v", err)
	}
	extraido, err := extrairTextoDeElemento(envelope, "nfseDadosMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento: %v", err)
	}
	if string(extraido) != string(xmlComEspeciais) {
		t.Fatalf("round-trip com especiais não bate:\n  esperado=%s\n  extraido=%s", xmlComEspeciais, extraido)
	}
}

// ── RecepcionarLoteRps (F4.8, Parte F) — mesmo padrão de prova do GerarNfse acima ───────────────

// TestMontarEnvelopeRecepcionarLoteRps_WrapperEhRecepcionarLoteRpsRequest ancora o nome do
// elemento-wrapper usado — DEDUÇÃO por convenção (ver comentário de
// MontarEnvelopeRecepcionarLoteRps), não confirmado por WSDL remoto. Este teste prende o nome
// atual; se um WSDL real algum dia desmentir, o teste é o primeiro a acusar.
func TestMontarEnvelopeRecepcionarLoteRps_WrapperEhRecepcionarLoteRpsRequest(t *testing.T) {
	envelope, err := MontarEnvelopeRecepcionarLoteRps([]byte(`<a/>`), "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeRecepcionarLoteRps: %v", err)
	}
	if !strings.Contains(string(envelope), ":RecepcionarLoteRpsRequest") {
		t.Fatalf("envelope não contém o wrapper RecepcionarLoteRpsRequest:\n%s", envelope)
	}
}

// TestMontarEnvelopeRecepcionarLoteRps_RoundTripByteIdentico — mesma prova central do GerarNfse:
// o XML extraído de volta do envelope (nfseDadosMsg, des-escapado) é BYTE-IDÊNTICO ao assinado.
func TestMontarEnvelopeRecepcionarLoteRps_RoundTripByteIdentico(t *testing.T) {
	caminho := filepath.Join("..", "testdata", "xml", "lote-assinado-a.xml")
	xmlAssinado, err := os.ReadFile(caminho)
	if err != nil {
		t.Fatalf("lendo %s: %v", caminho, err)
	}

	envelope, err := MontarEnvelopeRecepcionarLoteRps(xmlAssinado, "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeRecepcionarLoteRps: %v", err)
	}

	extraido, err := extrairTextoDeElemento(envelope, "nfseDadosMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento(nfseDadosMsg): %v", err)
	}

	if string(extraido) != string(xmlAssinado) {
		t.Fatalf("round-trip não bate: extraído (%d bytes) != assinado (%d bytes)", len(extraido), len(xmlAssinado))
	}
}

// TestMontarEnvelopeRecepcionarLoteRps_CabecalhoRoundTrip confere o nfseCabecMsg, mesmo padrão.
func TestMontarEnvelopeRecepcionarLoteRps_CabecalhoRoundTrip(t *testing.T) {
	envelope, err := MontarEnvelopeRecepcionarLoteRps([]byte(`<a/>`), "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeRecepcionarLoteRps: %v", err)
	}

	extraido, err := extrairTextoDeElemento(envelope, "nfseCabecMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento(nfseCabecMsg): %v", err)
	}

	esperado := montarCabecalho("2.04")
	if string(extraido) != string(esperado) {
		t.Fatalf("cabeçalho não bate:\n  esperado=%s\n  extraido=%s", esperado, extraido)
	}
}

// TestMontarEnvelopeRecepcionarLoteRps_EscapaCaracteresEspeciais — mesmo caso do GerarNfse.
func TestMontarEnvelopeRecepcionarLoteRps_EscapaCaracteresEspeciais(t *testing.T) {
	xmlComEspeciais := []byte(`<a attr="x&amp;y">GENERICA &amp; CIA &lt;TESTE&gt; "aspas" 'apostrofo'</a>`)

	envelope, err := MontarEnvelopeRecepcionarLoteRps(xmlComEspeciais, "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeRecepcionarLoteRps: %v", err)
	}
	extraido, err := extrairTextoDeElemento(envelope, "nfseDadosMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento: %v", err)
	}
	if string(extraido) != string(xmlComEspeciais) {
		t.Fatalf("round-trip com especiais não bate:\n  esperado=%s\n  extraido=%s", xmlComEspeciais, extraido)
	}
}

// ── ConsultarLoteRps (F4.11) — mesmo padrão de prova do GerarNfse/RecepcionarLoteRps acima ──────

func TestMontarEnvelopeConsultarLoteRps_WrapperEhConsultarLoteRpsRequest(t *testing.T) {
	envelope, err := MontarEnvelopeConsultarLoteRps([]byte(`<a/>`), "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeConsultarLoteRps: %v", err)
	}
	if !strings.Contains(string(envelope), ":ConsultarLoteRpsRequest") {
		t.Fatalf("envelope não contém o wrapper ConsultarLoteRpsRequest:\n%s", envelope)
	}
}

func TestMontarEnvelopeConsultarLoteRps_RoundTripByteIdentico(t *testing.T) {
	envio := MontarConsultarLoteRpsEnvio("12345678000199", "123456", "3074577")

	envelope, err := MontarEnvelopeConsultarLoteRps(envio, "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeConsultarLoteRps: %v", err)
	}

	extraido, err := extrairTextoDeElemento(envelope, "nfseDadosMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento(nfseDadosMsg): %v", err)
	}

	if string(extraido) != string(envio) {
		t.Fatalf("round-trip não bate: extraído (%d bytes) != envio (%d bytes)", len(extraido), len(envio))
	}
}

func TestMontarEnvelopeConsultarLoteRps_CabecalhoRoundTrip(t *testing.T) {
	envelope, err := MontarEnvelopeConsultarLoteRps([]byte(`<a/>`), "2.04")
	if err != nil {
		t.Fatalf("MontarEnvelopeConsultarLoteRps: %v", err)
	}

	extraido, err := extrairTextoDeElemento(envelope, "nfseCabecMsg")
	if err != nil {
		t.Fatalf("extrairTextoDeElemento(nfseCabecMsg): %v", err)
	}

	esperado := montarCabecalho("2.04")
	if string(extraido) != string(esperado) {
		t.Fatalf("cabeçalho não bate:\n  esperado=%s\n  extraido=%s", esperado, extraido)
	}
}

// TestMontarConsultarLoteRpsEnvio_EstruturaEOrdemDosNamespaces confere a MEDIÇÃO do item 2/XSD: só
// Prestador (CpfCnpj+InscricaoMunicipal opcional) e Protocolo — SEM NumeroLote — e os prefixos
// certos (p: pro que é local ao schema do envio, p1: pro que vem de tipos:tcIdentificacaoPessoaEmpresa).
func TestMontarConsultarLoteRpsEnvio_EstruturaEOrdemDosNamespaces(t *testing.T) {
	got := string(MontarConsultarLoteRpsEnvio("12345678000199", "123456", "3074577"))
	for _, trecho := range []string{
		"<p:ConsultarLoteRpsEnvio",
		"<p:Prestador>",
		"<p1:CpfCnpj><p1:Cnpj>12345678000199</p1:Cnpj></p1:CpfCnpj>",
		"<p1:InscricaoMunicipal>123456</p1:InscricaoMunicipal>",
		"</p:Prestador>",
		"<p:Protocolo>3074577</p:Protocolo>",
	} {
		if !strings.Contains(got, trecho) {
			t.Errorf("envio não contém %q:\n%s", trecho, got)
		}
	}
	if strings.Contains(got, "NumeroLote") {
		t.Errorf("🔴 ConsultarLoteRpsEnvio não deveria ter NumeroLote (XSD só pede Prestador+Protocolo):\n%s", got)
	}
}

func TestMontarConsultarLoteRpsEnvio_InscricaoMunicipalOpcionalOmiteQuandoVazia(t *testing.T) {
	got := string(MontarConsultarLoteRpsEnvio("12345678000199", "", "3074577"))
	if strings.Contains(got, "InscricaoMunicipal") {
		t.Errorf("🔴 InscricaoMunicipal vazia não deveria aparecer: %s", got)
	}
}
