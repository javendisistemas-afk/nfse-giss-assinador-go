// Package transmissor envia o XML de NFS-e assinado para o ambiente de
// HOMOLOGAÇÃO da GISS (GerarNfse), via SOAP 1.1 com mTLS. Nenhum efeito
// fiscal — endpoint fixo, sem exceção (ver EndpointHomologacao).
package transmissor

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// montarRequisicao monta o *http.Request POST para `url` com o envelope e os
// headers SOAP 1.1 corretos (Content-Type, SOAPAction). Função pura de
// construção — não faz a chamada, não valida endpoint. Separada de Enviar
// para poder ser testada contra um servidor local (httptest), já que Enviar
// só aceita EndpointHomologacao por desenho.
//
// soapAction é parâmetro (F4.8, Parte F) — antes era fixo em
// SOAPActionGerarNfse, o que impedia QUALQUER outra operação sem mudar este
// arquivo; agora quem monta o envelope (MontarEnvelopeGerarNfse,
// MontarEnvelopeRecepcionarLoteRps, ...) escolhe o SOAPAction que casa com
// ele.
func montarRequisicao(url string, envelope []byte, soapAction string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("transmissor: montando requisição: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"`+soapAction+`"`)
	return req, nil
}

// Enviar faz UMA requisição HTTP POST ao endpoint de homologação com o
// envelope já montado (ver MontarEnvelopeGerarNfse/MontarEnvelopeRecepcionarLoteRps) e o
// SOAPAction da MESMA operação (SOAPActionGerarNfse/SOAPActionRecepcionarLoteRps), autenticada por
// mTLS via `cliente` (ver ClienteMTLS). Devolve o status HTTP e o corpo bruto da resposta — quem
// chama decide o que fazer com eles (salvar em disco, interpretar).
func Enviar(cliente *http.Client, envelope []byte, soapAction string) (status int, respostaBruta []byte, err error) {
	return enviarEm(EndpointHomologacao, validarEndpoint, cliente, envelope, soapAction)
}

// EnviarProducao (F4.23) é IGUAL a Enviar, mas pro endpoint de PRODUÇÃO — que é PARÂMETRO do
// chamador (F7.12: esta lib é pública e atende qualquer município GISS, nunca um em particular;
// quem sabe qual é o endpoint real de produção, e faz a allowlist por valor exato contra host
// disfarçado/parecido, é o código privado de quem chama). validarEndpointProducao só faz a
// checagem genérica (https, não vazio). Só deve ser chamada quando o comando recebe
// -producao-confirmado; sem a flag, quem envia é Enviar, e Enviar nunca alcança produção.
func EnviarProducao(cliente *http.Client, endpointProducao string, envelope []byte, soapAction string) (status int, respostaBruta []byte, err error) {
	return enviarEm(endpointProducao, validarEndpointProducao, cliente, envelope, soapAction)
}

// enviarEm é o corpo comum: valida o endpoint ANTES de montar a requisição e faz UMA chamada.
func enviarEm(url string, validar func(string) error, cliente *http.Client, envelope []byte, soapAction string) (status int, respostaBruta []byte, err error) {
	if err := validar(url); err != nil {
		return 0, nil, err
	}

	req, err := montarRequisicao(url, envelope, soapAction)
	if err != nil {
		return 0, nil, err
	}

	resp, err := cliente.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("transmissor: enviando requisição: %w", err)
	}
	defer resp.Body.Close()

	corpo, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("transmissor: lendo resposta: %w", err)
	}
	return resp.StatusCode, corpo, nil
}
