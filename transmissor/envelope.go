package transmissor

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	nsSOAPEnvelope = "http://schemas.xmlsoap.org/soap/envelope/"
	nsAbrasf       = "http://nfse.abrasf.org.br"
	nsCabecalho    = "http://www.giss.com.br/cabecalho-v2_04.xsd"
)

// montarCabecalho monta a área de cabeçalho ABRASF — medida em
// cabecalho-v2_04.xsd: elemento raiz "cabecalho", atributo "versao"
// (obrigatório), filho "versaoDados" com o mesmo valor.
func montarCabecalho(versao string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<cabecalho xmlns="%s" versao="%s"><versaoDados>%s</versaoDados></cabecalho>`,
		nsCabecalho, versao, versao)
	return b.Bytes()
}

// MontarEnvelopeGerarNfse monta o envelope SOAP 1.1 da operação GerarNfse.
// Medido no WSDL local (nfse.wsdl.xml): SOAP 1.1 (xmlns soap =
// .../wsdl/soap/), style document, soapAction
// "http://nfse.abrasf.org.br/GerarNfse".
//
// 📌 FORNECIDO PELO PO (não medido por esta dupla — o nfse.wsdl remoto que
// define isso não é alcançável sem rede): o PO abriu o WSDL
// (?wsdl=nfse.wsdl) e colou o schema. No <xs:schema
// targetNamespace="http://nfse.abrasf.org.br"> SEM elementFormDefault (logo
// "unqualified" para elemento LOCAL):
//
//	<xs:element name="GerarNfseRequest" type="tns:input"/>
//	input = sequence(nfseCabecMsg: xs:string, nfseDadosMsg: xs:string)
//
// GerarNfseRequest é elemento GLOBAL — sempre qualificado (no namespace
// http://nfse.abrasf.org.br), independente de elementFormDefault (que só
// vale para elemento LOCAL). nfseCabecMsg/nfseDadosMsg são locais ao tipo
// "input" e elementFormDefault não foi setado → UNQUALIFIED (sem
// namespace), que é como este código já os monta (sem prefixo nem xmlns
// próprio) — só o NOME do wrapper mudou (era "GerarNfse", o pedido original
// desta fatia; o WSDL diz "GerarNfseRequest").
func MontarEnvelopeGerarNfse(xmlAssinado []byte, versaoCabecalho string) ([]byte, error) {
	cabecalho := montarCabecalho(versaoCabecalho)

	var cabecEsc, dadosEsc bytes.Buffer
	if err := xml.EscapeText(&cabecEsc, cabecalho); err != nil {
		return nil, fmt.Errorf("transmissor: escapando nfseCabecMsg: %w", err)
	}
	if err := xml.EscapeText(&dadosEsc, xmlAssinado); err != nil {
		return nil, fmt.Errorf("transmissor: escapando nfseDadosMsg: %w", err)
	}

	var env bytes.Buffer
	env.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	env.WriteString(`<soapenv:Envelope xmlns:soapenv="` + nsSOAPEnvelope + `" xmlns:ns="` + nsAbrasf + `">`)
	env.WriteString(`<soapenv:Header/>`)
	env.WriteString(`<soapenv:Body>`)
	env.WriteString(`<ns:GerarNfseRequest>`)
	env.WriteString(`<nfseCabecMsg>`)
	env.Write(cabecEsc.Bytes())
	env.WriteString(`</nfseCabecMsg>`)
	env.WriteString(`<nfseDadosMsg>`)
	env.Write(dadosEsc.Bytes())
	env.WriteString(`</nfseDadosMsg>`)
	env.WriteString(`</ns:GerarNfseRequest>`)
	env.WriteString(`</soapenv:Body>`)
	env.WriteString(`</soapenv:Envelope>`)

	return env.Bytes(), nil
}

// MontarEnvelopeRecepcionarLoteRps monta o envelope SOAP 1.1 da operação RecepcionarLoteRps.
//
// 📌 DEDUÇÃO, NÃO MEDIDA (F4.8, Parte F): o nome do wrapper (`RecepcionarLoteRpsRequest`) segue a
// MESMA convenção já confirmada pelo PO pra GerarNfse (operação+"Request", nfseCabecMsg/
// nfseDadosMsg sem namespace) — mas o WSDL remoto desta operação específica (o schema dentro de
// `<wsdl:types>`, alcançado só via `?wsdl=nfse.wsdl`) não está disponível localmente pra confirmar.
// Medido, com CONTROLE: os dois arquivos salvos em `wsdl_homolog/` (`nfse.wsdl.xml`,
// `nfse-ws.wsdl.xml`) têm ZERO ocorrência de `wsdl:types`/`xsd:schema` — são só o WSDL de BINDING
// (portas/operações/soapAction), não o de TIPOS. Controle: `GerarNfseRequest` (nome que SABEMOS
// correto, fornecido pelo PO na F4.3) também dá ZERO nesses arquivos — confirma que a ausência é
// do arquivo, não da busca.
// Suporte indireto (não é confirmação de fonte): o teste real da F4.7/F4.8 Parte E enviou um
// envelope com este wrapper e recebeu HTTP 200 com um erro de NEGÓCIO coerente (`E174`, via
// `MensagemRetorno` — o mesmo formato de resposta do GerarNfse) em vez de um SOAP Fault de operação
// desconhecida — compatível com o wrapper estar certo, mas não é prova de fonte.
func MontarEnvelopeRecepcionarLoteRps(xmlAssinado []byte, versaoCabecalho string) ([]byte, error) {
	cabecalho := montarCabecalho(versaoCabecalho)

	var cabecEsc, dadosEsc bytes.Buffer
	if err := xml.EscapeText(&cabecEsc, cabecalho); err != nil {
		return nil, fmt.Errorf("transmissor: escapando nfseCabecMsg: %w", err)
	}
	if err := xml.EscapeText(&dadosEsc, xmlAssinado); err != nil {
		return nil, fmt.Errorf("transmissor: escapando nfseDadosMsg: %w", err)
	}

	var env bytes.Buffer
	env.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	env.WriteString(`<soapenv:Envelope xmlns:soapenv="` + nsSOAPEnvelope + `" xmlns:ns="` + nsAbrasf + `">`)
	env.WriteString(`<soapenv:Header/>`)
	env.WriteString(`<soapenv:Body>`)
	env.WriteString(`<ns:RecepcionarLoteRpsRequest>`)
	env.WriteString(`<nfseCabecMsg>`)
	env.Write(cabecEsc.Bytes())
	env.WriteString(`</nfseCabecMsg>`)
	env.WriteString(`<nfseDadosMsg>`)
	env.Write(dadosEsc.Bytes())
	env.WriteString(`</nfseDadosMsg>`)
	env.WriteString(`</ns:RecepcionarLoteRpsRequest>`)
	env.WriteString(`</soapenv:Body>`)
	env.WriteString(`</soapenv:Envelope>`)

	return env.Bytes(), nil
}

// MontarEnvelopeConsultarLoteRps monta o envelope SOAP 1.1 da operação ConsultarLoteRps (F4.11).
//
// 📌 DEDUÇÃO, NÃO MEDIDA, mesma ressalva do MontarEnvelopeRecepcionarLoteRps: o wrapper
// (`ConsultarLoteRpsRequest`) segue a MESMA convenção já confirmada pra GerarNfse
// (operação+"Request", nfseCabecMsg/nfseDadosMsg sem namespace) — o WSDL remoto com o schema de
// tipos desta operação não está disponível localmente pra confirmar. Medido, com CONTROLE (mesmo
// teste já feito nas duas operações anteriores): `wsdl_homolog/` não tem `wsdl:types` nenhum —
// nem `ConsultarLoteRpsRequest` nem `GerarNfseRequest` (que SABEMOS correto) aparecem lá.
func MontarEnvelopeConsultarLoteRps(xmlEntrada []byte, versaoCabecalho string) ([]byte, error) {
	cabecalho := montarCabecalho(versaoCabecalho)

	var cabecEsc, dadosEsc bytes.Buffer
	if err := xml.EscapeText(&cabecEsc, cabecalho); err != nil {
		return nil, fmt.Errorf("transmissor: escapando nfseCabecMsg: %w", err)
	}
	if err := xml.EscapeText(&dadosEsc, xmlEntrada); err != nil {
		return nil, fmt.Errorf("transmissor: escapando nfseDadosMsg: %w", err)
	}

	var env bytes.Buffer
	env.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	env.WriteString(`<soapenv:Envelope xmlns:soapenv="` + nsSOAPEnvelope + `" xmlns:ns="` + nsAbrasf + `">`)
	env.WriteString(`<soapenv:Header/>`)
	env.WriteString(`<soapenv:Body>`)
	env.WriteString(`<ns:ConsultarLoteRpsRequest>`)
	env.WriteString(`<nfseCabecMsg>`)
	env.Write(cabecEsc.Bytes())
	env.WriteString(`</nfseCabecMsg>`)
	env.WriteString(`<nfseDadosMsg>`)
	env.Write(dadosEsc.Bytes())
	env.WriteString(`</nfseDadosMsg>`)
	env.WriteString(`</ns:ConsultarLoteRpsRequest>`)
	env.WriteString(`</soapenv:Body>`)
	env.WriteString(`</soapenv:Envelope>`)

	return env.Bytes(), nil
}

// extrairTextoDeElemento acha o PRIMEIRO elemento de nome local
// `nomeElemento` (em qualquer namespace/prefixo) em `doc` e devolve o
// conteúdo textual DES-ESCAPADO. Usado no teste de round-trip do envelope
// de requisição e na leitura da resposta.
func extrairTextoDeElemento(doc []byte, nomeElemento string) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("transmissor: elemento %q não encontrado: %w", nomeElemento, err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != nomeElemento {
			continue
		}
		var conteudo string
		if err := dec.DecodeElement(&conteudo, &start); err != nil {
			return nil, fmt.Errorf("transmissor: decodificando %q: %w", nomeElemento, err)
		}
		return []byte(conteudo), nil
	}
}
