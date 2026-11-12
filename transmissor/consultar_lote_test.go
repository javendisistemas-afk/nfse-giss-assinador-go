package transmissor

import "testing"

// Fixtures sintéticas de ConsultarLoteRpsResposta — estrutura medida direto de
// consultar-lote-rps-resposta-v2_04.xsd (F4.11): Situacao sempre + choice opcional de
// ListaNfse/ListaMensagemRetorno/ListaMensagemRetornoLote. Nenhum dado real do prestador.

const respostaConsultaLoteProcessando = `<?xml version="1.0"?>
<ns:ConsultarLoteRpsResposta xmlns:ns="http://www.giss.com.br/consultar-lote-rps-resposta-v2_04.xsd">
  <Situacao>2</Situacao>
</ns:ConsultarLoteRpsResposta>`

const respostaConsultaLoteAutorizada = `<?xml version="1.0"?>
<ns:ConsultarLoteRpsResposta xmlns:ns="http://www.giss.com.br/consultar-lote-rps-resposta-v2_04.xsd" xmlns:tp="http://www.giss.com.br/tipos-v2_04.xsd">
  <Situacao>4</Situacao>
  <tp:ListaNfse>
    <tp:CompNfse>
      <tp:Nfse><tp:InfNfse><tp:Numero>12345</tp:Numero><tp:CodigoVerificacao>ABCD1234</tp:CodigoVerificacao></tp:InfNfse></tp:Nfse>
    </tp:CompNfse>
  </tp:ListaNfse>
</ns:ConsultarLoteRpsResposta>`

const respostaConsultaLoteAutorizadaDuasNotas = `<?xml version="1.0"?>
<ns:ConsultarLoteRpsResposta xmlns:ns="http://www.giss.com.br/consultar-lote-rps-resposta-v2_04.xsd" xmlns:tp="http://www.giss.com.br/tipos-v2_04.xsd">
  <Situacao>4</Situacao>
  <tp:ListaNfse>
    <tp:CompNfse><tp:Nfse><tp:InfNfse><tp:Numero>111</tp:Numero><tp:CodigoVerificacao>AAA</tp:CodigoVerificacao></tp:InfNfse></tp:Nfse></tp:CompNfse>
    <tp:CompNfse><tp:Nfse><tp:InfNfse><tp:Numero>222</tp:Numero><tp:CodigoVerificacao>BBB</tp:CodigoVerificacao></tp:InfNfse></tp:Nfse></tp:CompNfse>
  </tp:ListaNfse>
</ns:ConsultarLoteRpsResposta>`

const respostaConsultaLoteRejeitada = `<?xml version="1.0"?>
<ns:ConsultarLoteRpsResposta xmlns:ns="http://www.giss.com.br/consultar-lote-rps-resposta-v2_04.xsd" xmlns:tp="http://www.giss.com.br/tipos-v2_04.xsd">
  <Situacao>3</Situacao>
  <tp:ListaMensagemRetorno>
    <tp:MensagemRetorno><tp:Codigo>E001</tp:Codigo><tp:Mensagem>erro de teste</tp:Mensagem><tp:Correcao>corrija isto</tp:Correcao></tp:MensagemRetorno>
  </tp:ListaMensagemRetorno>
</ns:ConsultarLoteRpsResposta>`

// respostaConsultaLoteRejeitadaPorRps — a variante ListaMensagemRetornoLote (tcMensagemRetornoLote:
// IdentificacaoRps+Codigo+Mensagem, SEM Correcao) — medida separadamente no XSD (F4.11, item 1).
const respostaConsultaLoteRejeitadaPorRps = `<?xml version="1.0"?>
<ns:ConsultarLoteRpsResposta xmlns:ns="http://www.giss.com.br/consultar-lote-rps-resposta-v2_04.xsd" xmlns:tp="http://www.giss.com.br/tipos-v2_04.xsd">
  <Situacao>3</Situacao>
  <tp:ListaMensagemRetornoLote>
    <tp:MensagemRetorno><tp:IdentificacaoRps><tp:Numero>1</tp:Numero></tp:IdentificacaoRps><tp:Codigo>E002</tp:Codigo><tp:Mensagem>erro por RPS</tp:Mensagem></tp:MensagemRetorno>
  </tp:ListaMensagemRetornoLote>
</ns:ConsultarLoteRpsResposta>`

func TestInterpretarRespostaConsultarLoteRps_Processando(t *testing.T) {
	r, err := InterpretarRespostaConsultarLoteRps([]byte(respostaConsultaLoteProcessando))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if r.Situacao != SituacaoLoteNaoProcessado {
		t.Errorf("Situacao = %q, esperava %q", r.Situacao, SituacaoLoteNaoProcessado)
	}
	if len(r.NotasAutorizadas) != 0 || len(r.Mensagens) != 0 {
		t.Errorf("🔴 processando não deveria ter notas nem mensagens: %+v", r)
	}
}

func TestInterpretarRespostaConsultarLoteRps_NaoRecebidoTambemContaComoProcessando(t *testing.T) {
	doc := `<ConsultarLoteRpsResposta><Situacao>1</Situacao></ConsultarLoteRpsResposta>`
	r, err := InterpretarRespostaConsultarLoteRps([]byte(doc))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if r.Situacao != SituacaoLoteNaoRecebido {
		t.Errorf("Situacao = %q, esperava %q", r.Situacao, SituacaoLoteNaoRecebido)
	}
}

func TestInterpretarRespostaConsultarLoteRps_Autorizada(t *testing.T) {
	r, err := InterpretarRespostaConsultarLoteRps([]byte(respostaConsultaLoteAutorizada))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if r.Situacao != SituacaoLoteProcessadoOK {
		t.Errorf("Situacao = %q, esperava %q", r.Situacao, SituacaoLoteProcessadoOK)
	}
	if len(r.NotasAutorizadas) != 1 {
		t.Fatalf("NotasAutorizadas = %+v, esperava 1", r.NotasAutorizadas)
	}
	if r.NotasAutorizadas[0].NumeroNfse != "12345" || r.NotasAutorizadas[0].CodigoVerificacao != "ABCD1234" {
		t.Errorf("nota = %+v", r.NotasAutorizadas[0])
	}
	if len(r.Mensagens) != 0 {
		t.Errorf("🔴 autorizada não deveria ter mensagens de erro: %+v", r.Mensagens)
	}
}

// respostaConsultaLoteAutorizadaComEnderecos — F4.40 (achado em produção, RPS 296, 22/10/2026):
// estrutura REAL de um CompNfse autorizado (medida em 290.xml, uma NFS-e real), com os DOIS
// blocos de endereço que colidem com <Numero> da nota: o do PRESTADOR (número da casa 890,
// ordem no XSD ANTES da declaração) e o do TOMADOR (número da casa 1500, DEPOIS — era este que
// vencia antes da correção, por ser o último em ordem de documento). O número real da NFS-e é
// 296, propositalmente colocado para bater com o achado de verdade.
const respostaConsultaLoteAutorizadaComEnderecos = `<?xml version="1.0"?>
<ns:ConsultarLoteRpsResposta xmlns:ns="http://www.giss.com.br/consultar-lote-rps-resposta-v2_04.xsd" xmlns:tp="http://www.giss.com.br/tipos-v2_04.xsd">
  <Situacao>4</Situacao>
  <tp:ListaNfse>
    <tp:CompNfse>
      <tp:Nfse>
        <tp:InfNfse>
          <tp:Numero>296</tp:Numero>
          <tp:CodigoVerificacao>TVELYRLBF</tp:CodigoVerificacao>
          <tp:PrestadorServico>
            <tp:Endereco>
              <tp:Endereco>R TIRADENTES</tp:Endereco>
              <tp:Numero>890</tp:Numero>
            </tp:Endereco>
          </tp:PrestadorServico>
          <tp:DeclaracaoPrestacaoServico>
            <tp:InfDeclaracaoPrestacaoServico>
              <tp:TomadorServico>
                <tp:Endereco>
                  <tp:Endereco>Rua Exemplo</tp:Endereco>
                  <tp:Numero>1500</tp:Numero>
                </tp:Endereco>
              </tp:TomadorServico>
            </tp:InfDeclaracaoPrestacaoServico>
          </tp:DeclaracaoPrestacaoServico>
        </tp:InfNfse>
      </tp:Nfse>
    </tp:CompNfse>
  </tp:ListaNfse>
</ns:ConsultarLoteRpsResposta>`

// TestInterpretarRespostaConsultarLoteRps_AutorizadaNaoConfundeNumeroComEnderecos — a prova de
// regressão do F4.40: com os dois endereços presentes (prestador E tomador, cada um com seu
// próprio <Numero> de casa), o número extraído tem de ser o da NFS-e (296), nunca o de um
// endereço (890/1500). CodigoVerificacao continua certo (TVELYRLBF) — controle de que a correção
// não quebrou o que já funcionava.
func TestInterpretarRespostaConsultarLoteRps_AutorizadaNaoConfundeNumeroComEnderecos(t *testing.T) {
	r, err := InterpretarRespostaConsultarLoteRps([]byte(respostaConsultaLoteAutorizadaComEnderecos))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(r.NotasAutorizadas) != 1 {
		t.Fatalf("NotasAutorizadas = %+v, esperava 1", r.NotasAutorizadas)
	}
	nota := r.NotasAutorizadas[0]
	if nota.NumeroNfse != "296" {
		t.Fatalf("🔴 NumeroNfse = %q, esperava %q (F4.40: pegou o número de um ENDEREÇO em vez do "+
			"número da nota — RPS 296 em produção extraiu 890, o número da casa)", nota.NumeroNfse, "296")
	}
	if nota.CodigoVerificacao != "TVELYRLBF" {
		t.Fatalf("CodigoVerificacao = %q, esperava %q", nota.CodigoVerificacao, "TVELYRLBF")
	}
}

func TestInterpretarRespostaConsultarLoteRps_AutorizadaComDuasNotas(t *testing.T) {
	r, err := InterpretarRespostaConsultarLoteRps([]byte(respostaConsultaLoteAutorizadaDuasNotas))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(r.NotasAutorizadas) != 2 {
		t.Fatalf("🔴 NotasAutorizadas = %+v, esperava 2 (ListaNfse/CompNfse é maxOccurs=unbounded)", r.NotasAutorizadas)
	}
	if r.NotasAutorizadas[0].NumeroNfse != "111" || r.NotasAutorizadas[1].NumeroNfse != "222" {
		t.Errorf("notas fora de ordem: %+v", r.NotasAutorizadas)
	}
}

func TestInterpretarRespostaConsultarLoteRps_Rejeitada(t *testing.T) {
	r, err := InterpretarRespostaConsultarLoteRps([]byte(respostaConsultaLoteRejeitada))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if r.Situacao != SituacaoLoteProcessadoComErro {
		t.Errorf("Situacao = %q, esperava %q", r.Situacao, SituacaoLoteProcessadoComErro)
	}
	if len(r.Mensagens) != 1 || r.Mensagens[0].Codigo != "E001" || r.Mensagens[0].Correcao != "corrija isto" {
		t.Errorf("Mensagens = %+v", r.Mensagens)
	}
	if len(r.NotasAutorizadas) != 0 {
		t.Errorf("🔴 rejeitada não deveria ter notas autorizadas: %+v", r.NotasAutorizadas)
	}
}

func TestInterpretarRespostaConsultarLoteRps_RejeitadaPorRpsSemCorrecao(t *testing.T) {
	r, err := InterpretarRespostaConsultarLoteRps([]byte(respostaConsultaLoteRejeitadaPorRps))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(r.Mensagens) != 1 || r.Mensagens[0].Codigo != "E002" || r.Mensagens[0].Mensagem != "erro por RPS" {
		t.Errorf("Mensagens = %+v", r.Mensagens)
	}
	if r.Mensagens[0].Correcao != "" {
		t.Errorf("🔴 tcMensagemRetornoLote não tem Correcao no XSD — devia ficar vazio, veio %q", r.Mensagens[0].Correcao)
	}
}

func TestInterpretarRespostaConsultarLoteRps_SemSituacaoEhErro(t *testing.T) {
	_, err := InterpretarRespostaConsultarLoteRps([]byte(`<a><b>x</b></a>`))
	if err == nil {
		t.Fatal("🔴 resposta sem Situacao passou sem erro")
	}
}

// TestInterpretarRespostaConsultarLoteRps_FormatoOutputXML — mesma camada ESCAPADA que o
// GerarNfse/RecepcionarLoteRps usam (o SOAP body real envolve a resposta num outputXML string).
func TestInterpretarRespostaConsultarLoteRps_FormatoOutputXML(t *testing.T) {
	envelope := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:ConsultarLoteRpsResponse xmlns:ns="http://nfse.abrasf.org.br"><outputXML>&lt;Situacao&gt;4&lt;/Situacao&gt;&lt;ListaNfse&gt;&lt;CompNfse&gt;&lt;Nfse&gt;&lt;InfNfse&gt;&lt;Numero&gt;999&lt;/Numero&gt;&lt;CodigoVerificacao&gt;ZZZ&lt;/CodigoVerificacao&gt;&lt;/InfNfse&gt;&lt;/Nfse&gt;&lt;/CompNfse&gt;&lt;/ListaNfse&gt;</outputXML></ns:ConsultarLoteRpsResponse></soapenv:Body></soapenv:Envelope>`
	r, err := InterpretarRespostaConsultarLoteRps([]byte(envelope))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if len(r.NotasAutorizadas) != 1 || r.NotasAutorizadas[0].NumeroNfse != "999" {
		t.Errorf("NotasAutorizadas = %+v", r.NotasAutorizadas)
	}
}
