package transmissor

import (
	"errors"
	"fmt"
	"strings"
)

// EndpointHomologacao é o ÚNICO endpoint que este agente aceita enviar,
// nesta fatia (F4.3 — só homologação, sem efeito fiscal). Medido no WSDL
// local (C:\sistemas\outros\arquivos_nfs\wsdl_homolog\nfse.wsdl.xml):
// <soap:address location="https://v2-ws-homologacao.giss.com.br/service-ws/nf/nfse-ws"/>
const EndpointHomologacao = "https://v2-ws-homologacao.giss.com.br/service-ws/nf/nfse-ws"

// SOAPActionGerarNfse — medido no mesmo WSDL, operação GerarNfse.
const SOAPActionGerarNfse = "http://nfse.abrasf.org.br/GerarNfse"

// SOAPActionRecepcionarLoteRps — medido no mesmo WSDL local
// (wsdl_homolog/nfse.wsdl.xml), operação RecepcionarLoteRps:
// <wsdl:operation name="RecepcionarLoteRps"><soap:operation
// soapAction="http://nfse.abrasf.org.br/RecepcionarLoteRps" .../>
const SOAPActionRecepcionarLoteRps = "http://nfse.abrasf.org.br/RecepcionarLoteRps"

// SOAPActionConsultarLoteRps — medido no mesmo WSDL local, operação ConsultarLoteRps (F4.11):
// <wsdl:operation name="ConsultarLoteRps"><soap:operation
// soapAction="http://nfse.abrasf.org.br/ConsultarLoteRps" .../>
const SOAPActionConsultarLoteRps = "http://nfse.abrasf.org.br/ConsultarLoteRps"

var ErrEndpointNaoPermitido = errors.New("transmissor: endpoint fora do permitido (só homologação)")

var ErrEndpointProducaoNaoPermitido = errors.New("transmissor: endpoint de produção inválido (precisa ser https, não vazio)")

// validarEndpoint reprova qualquer URL que não seja EXATAMENTE
// EndpointHomologacao — nunca produção, nunca um host "parecido".
func validarEndpoint(url string) error {
	if url != EndpointHomologacao {
		return fmt.Errorf("%w: %q", ErrEndpointNaoPermitido, url)
	}
	return nil
}

// validarEndpointProducao faz a checagem mínima que esta lib, pública e genérica para qualquer
// município GISS, pode fazer sozinha: reprova vazio e reprova "http" simples. QUAL é o endpoint
// certo (allowlist por valor exato, defesa contra host disfarçado/parecido) é responsabilidade de
// quem chama EnviarProducao — esta lib não conhece nenhum município em particular (F7.12).
func validarEndpointProducao(url string) error {
	if url == "" || !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("%w: %q", ErrEndpointProducaoNaoPermitido, url)
	}
	return nil
}
