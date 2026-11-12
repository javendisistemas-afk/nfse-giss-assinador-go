package transmissor

import (
	"bytes"
	"encoding/xml"
	"testing"
)

// TestInterpretarResposta_FormatoOutputXML_* é o caminho PRIMÁRIO, fornecido
// pelo PO: GerarNfseResponse = sequence(outputXML: xs:string), outputXML
// carregando o GerarNfseResposta ESCAPADO.

func TestInterpretarResposta_FormatoOutputXML_Autorizada(t *testing.T) {
	gerarNfseResposta := `<GerarNfseResposta xmlns="http://www.giss.com.br/gerar-nfse-resposta-v2_04.xsd"><ListaNfse><tipos:CompNfse xmlns:tipos="http://www.giss.com.br/tipos-v2_04.xsd"><tipos:Nfse><tipos:InfNfse><tipos:Numero>123</tipos:Numero><tipos:CodigoVerificacao>ABCD1234</tipos:CodigoVerificacao></tipos:InfNfse></tipos:Nfse></tipos:CompNfse></ListaNfse></GerarNfseResposta>`
	envelope := montarEnvelopeRespostaParaTeste(t, gerarNfseResposta)

	r, err := InterpretarResposta(envelope)
	if err != nil {
		t.Fatalf("InterpretarResposta: %v", err)
	}
	if !r.Autorizada {
		t.Fatal("esperava Autorizada=true")
	}
	if r.NumeroNfse != "123" || r.CodigoVerificacao != "ABCD1234" {
		t.Fatalf("Numero/CodigoVerificacao = %q/%q", r.NumeroNfse, r.CodigoVerificacao)
	}
}

// TestInterpretarResposta_AutorizadaNaoConfundeNumeroComEnderecos — F4.40 (mesmo achado do
// extrairConsultaLoteResultado, RPS 296 em produção, 22/10/2026): extrairResultado nem tinha o
// `dentroCompNfse` que o outro parser já tinha — qualquer <Numero> no documento (endereço do
// prestador OU do tomador) sobrescrevia r.NumeroNfse. Fixture com os DOIS endereços presentes,
// estrutura medida em 290.xml (uma NFS-e real autorizada).
func TestInterpretarResposta_AutorizadaNaoConfundeNumeroComEnderecos(t *testing.T) {
	gerarNfseResposta := `<GerarNfseResposta xmlns="http://www.giss.com.br/gerar-nfse-resposta-v2_04.xsd"><ListaNfse><tipos:CompNfse xmlns:tipos="http://www.giss.com.br/tipos-v2_04.xsd"><tipos:Nfse><tipos:InfNfse><tipos:Numero>296</tipos:Numero><tipos:CodigoVerificacao>TVELYRLBF</tipos:CodigoVerificacao><tipos:PrestadorServico><tipos:Endereco><tipos:Endereco>R TIRADENTES</tipos:Endereco><tipos:Numero>890</tipos:Numero></tipos:Endereco></tipos:PrestadorServico><tipos:DeclaracaoPrestacaoServico><tipos:InfDeclaracaoPrestacaoServico><tipos:TomadorServico><tipos:Endereco><tipos:Endereco>Rua Exemplo</tipos:Endereco><tipos:Numero>1500</tipos:Numero></tipos:Endereco></tipos:TomadorServico></tipos:InfDeclaracaoPrestacaoServico></tipos:DeclaracaoPrestacaoServico></tipos:InfNfse></tipos:Nfse></tipos:CompNfse></ListaNfse></GerarNfseResposta>`
	envelope := montarEnvelopeRespostaParaTeste(t, gerarNfseResposta)

	r, err := InterpretarResposta(envelope)
	if err != nil {
		t.Fatalf("InterpretarResposta: %v", err)
	}
	if !r.Autorizada {
		t.Fatal("esperava Autorizada=true")
	}
	if r.NumeroNfse != "296" {
		t.Fatalf("🔴 NumeroNfse = %q, esperava %q (F4.40: pegou o número de um ENDEREÇO em vez do "+
			"número da nota)", r.NumeroNfse, "296")
	}
	if r.CodigoVerificacao != "TVELYRLBF" {
		t.Fatalf("CodigoVerificacao = %q, esperava %q", r.CodigoVerificacao, "TVELYRLBF")
	}
}

func TestInterpretarResposta_FormatoOutputXML_Reprovada(t *testing.T) {
	gerarNfseResposta := `<GerarNfseResposta xmlns="http://www.giss.com.br/gerar-nfse-resposta-v2_04.xsd"><tipos:ListaMensagemRetorno xmlns:tipos="http://www.giss.com.br/tipos-v2_04.xsd"><tipos:MensagemRetorno><tipos:Codigo>E002</tipos:Codigo><tipos:Mensagem>CNPJ inválido</tipos:Mensagem><tipos:Correcao>confira o CNPJ</tipos:Correcao></tipos:MensagemRetorno></tipos:ListaMensagemRetorno></GerarNfseResposta>`
	envelope := montarEnvelopeRespostaParaTeste(t, gerarNfseResposta)

	r, err := InterpretarResposta(envelope)
	if err != nil {
		t.Fatalf("InterpretarResposta: %v", err)
	}
	if r.Autorizada {
		t.Fatal("esperava Autorizada=false")
	}
	if len(r.Mensagens) != 1 || r.Mensagens[0].Codigo != "E002" || r.Mensagens[0].Mensagem != "CNPJ inválido" {
		t.Fatalf("Mensagens = %+v", r.Mensagens)
	}
}

// TestInterpretarResposta_FormatoLoteRecebido_RecepcionarLoteRps — F4.11: o formato de SUCESSO do
// RecepcionarLoteRps (EnviarLoteRpsResposta, achado F4.10) não tem CompNfse nem MensagemRetorno —
// antes disto caía no erro genérico "não achei...". Fixture medida no XSD
// enviar-lote-rps-resposta-v2_04.xsd: NumeroLote+DataRecebimento+Protocolo.
func TestInterpretarResposta_FormatoLoteRecebido_RecepcionarLoteRps(t *testing.T) {
	enviarLoteResposta := `<ns3:EnviarLoteRpsResposta xmlns:ns3="http://www.giss.com.br/enviar-lote-rps-resposta-v2_04.xsd"><ns3:NumeroLote>1</ns3:NumeroLote><ns3:DataRecebimento>2026-10-02T13:35:36.913-03:00</ns3:DataRecebimento><ns3:Protocolo>3074577</ns3:Protocolo></ns3:EnviarLoteRpsResposta>`
	envelope := montarEnvelopeRespostaParaTeste(t, enviarLoteResposta)

	r, err := InterpretarResposta(envelope)
	if err != nil {
		t.Fatalf("InterpretarResposta: %v", err)
	}
	if !r.LoteRecebido {
		t.Fatal("esperava LoteRecebido=true")
	}
	if r.Autorizada {
		t.Error("🔴 lote recebido NÃO é autorizada — RecepcionarLoteRps é assíncrono")
	}
	if r.NumeroLote != "1" || r.Protocolo != "3074577" || r.DataRecebimento != "2026-10-02T13:35:36.913-03:00" {
		t.Errorf("NumeroLote/Protocolo/DataRecebimento = %q/%q/%q", r.NumeroLote, r.Protocolo, r.DataRecebimento)
	}
	if len(r.Mensagens) != 0 {
		t.Errorf("🔴 lote recebido não deveria ter mensagens de erro: %+v", r.Mensagens)
	}
}

// montarEnvelopeRespostaParaTeste embrulha gerarNfseRespostaXML (escapado,
// via encoding/xml — mesma peça que a produção usa) dentro de
// <outputXML>, no formato que o PO forneceu para GerarNfseResponse.
func montarEnvelopeRespostaParaTeste(t *testing.T, gerarNfseRespostaXML string) []byte {
	t.Helper()
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, []byte(gerarNfseRespostaXML)); err != nil {
		t.Fatalf("escapando resposta de teste: %v", err)
	}
	var env bytes.Buffer
	env.WriteString(`<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:GerarNfseResponse xmlns:ns="http://nfse.abrasf.org.br"><outputXML>`)
	env.Write(esc.Bytes())
	env.WriteString(`</outputXML></ns:GerarNfseResponse></soapenv:Body></soapenv:Envelope>`)
	return env.Bytes()
}
