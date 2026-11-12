package transmissor

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// MensagemRetorno espelha tcMensagemRetorno (tipos-v2_04.xsd).
type MensagemRetorno struct {
	Codigo   string
	Mensagem string
	Correcao string
}

// Resultado é a leitura da resposta do GerarNfse: ou Autorizada (com
// NumeroNfse/CodigoVerificacao), ou reprovada (Mensagens, uma ou mais).
//
// LoteRecebido (F4.11): RecepcionarLoteRps é ASSÍNCRONO — isto NÃO é autorização nem reprovação,
// só confirma que o lote foi RECEBIDO pela GISS pra processamento (EnviarLoteRpsResposta, achado
// F4.10: NumeroLote/DataRecebimento/Protocolo, SEM CompNfse nem MensagemRetorno — por isso o
// InterpretarResposta de antes não reconhecia esse formato). A autorização de fato vem depois,
// via ConsultarLoteRps (ver ResultadoConsultaLote).
type Resultado struct {
	Autorizada        bool
	NumeroNfse        string
	CodigoVerificacao string
	Mensagens         []MensagemRetorno

	LoteRecebido    bool
	NumeroLote      string
	Protocolo       string
	DataRecebimento string
}

// InterpretarResposta lê a resposta bruta do GerarNfse.
//
// 📌 FORNECIDO PELO PO (não medido por esta dupla): GerarNfseResponse ==
// sequence(outputXML: xs:string) — outputXML é LOCAL ao tipo "output" e
// unqualified (sem namespace), carregando o GerarNfseResposta ESCAPADO como
// texto (mesmo padrão cabeç+dados do pedido). Por isso o caminho primário é
// extrair <outputXML> e interpretar o texto de dentro dele.
//
// Mantém, como FALLBACK, a tentativa direta (CompNfse/MensagemRetorno sem
// estar dentro de outputXML) e a concatenação de todo o texto do documento —
// cobre o caso de a resposta não seguir esse schema (ex.: SOAP Fault).
func InterpretarResposta(respostaBruta []byte) (*Resultado, error) {
	if outputXML, err := extrairTextoDeElemento(respostaBruta, "outputXML"); err == nil {
		if r, achou := extrairResultado(outputXML); achou {
			return r, nil
		}
		if r, achou := extrairLoteRecebido(outputXML); achou {
			return r, nil
		}
	}

	if r, achou := extrairResultado(respostaBruta); achou {
		return r, nil
	}
	if r, achou := extrairLoteRecebido(respostaBruta); achou {
		return r, nil
	}

	texto := strings.TrimSpace(todoTextoConcatenado(respostaBruta))
	if strings.HasPrefix(texto, "<") {
		if r, achou := extrairResultado([]byte(texto)); achou {
			return r, nil
		}
		if r, achou := extrairLoteRecebido([]byte(texto)); achou {
			return r, nil
		}
	}

	return nil, fmt.Errorf("transmissor: não achei CompNfse nem MensagemRetorno na resposta (nem em outputXML, nem direto, nem em texto embutido)")
}

// extrairLoteRecebido reconhece o formato de SUCESSO do RecepcionarLoteRps (EnviarLoteRpsResposta,
// medido no XSD enviar-lote-rps-resposta-v2_04.xsd: NumeroLote + DataRecebimento + Protocolo, em
// xsd:sequence — os TRÊS sempre juntos quando é sucesso, nunca CompNfse nem MensagemRetorno).
func extrairLoteRecebido(doc []byte) (*Resultado, bool) {
	r := &Resultado{}
	achouNumeroLote, achouProtocolo := false, false
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "NumeroLote":
			var v string
			if dec.DecodeElement(&v, &start) == nil {
				r.NumeroLote = v
				achouNumeroLote = true
			}
		case "Protocolo":
			var v string
			if dec.DecodeElement(&v, &start) == nil {
				r.Protocolo = v
				achouProtocolo = true
			}
		case "DataRecebimento":
			var v string
			if dec.DecodeElement(&v, &start) == nil {
				r.DataRecebimento = v
			}
		}
	}
	if achouNumeroLote && achouProtocolo {
		r.LoteRecebido = true
		return r, true
	}
	return nil, false
}

// extrairResultado — mesmo defeito do extrairConsultaLoteResultado (F4.40, 22/10/2026, RPS 296),
// AQUI AINDA MAIS EXPOSTO: nem o `dentroCompNfse` havia — QUALQUER <Numero> no documento
// (endereço do prestador, endereço do tomador, o que vier) sobrescrevia r.NumeroNfse, ganhando o
// ÚLTIMO em ordem de documento. Mesma correção: só aceita Numero/CodigoVerificacao DENTRO de
// CompNfse e FORA de qualquer bloco Endereco (enderecoDepth é contador, não bool — Endereco
// aparece aninhado em Endereco no próprio XSD).
func extrairResultado(doc []byte) (*Resultado, bool) {
	r := &Resultado{}
	achou := false
	dentroCompNfse := false
	enderecoDepth := 0
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "CompNfse":
				r.Autorizada = true
				achou = true
				dentroCompNfse = true
			case "Endereco":
				enderecoDepth++
			case "Numero":
				if dentroCompNfse && enderecoDepth == 0 && r.NumeroNfse == "" {
					var v string
					if dec.DecodeElement(&v, &t) == nil && v != "" {
						r.NumeroNfse = v
					}
				}
			case "CodigoVerificacao":
				if dentroCompNfse && enderecoDepth == 0 {
					var v string
					if dec.DecodeElement(&v, &t) == nil {
						r.CodigoVerificacao = v
					}
				}
			case "MensagemRetorno":
				var m struct{ Codigo, Mensagem, Correcao string }
				if dec.DecodeElement(&m, &t) == nil {
					r.Mensagens = append(r.Mensagens, MensagemRetorno(m))
					achou = true
				}
			}
		case xml.EndElement:
			if t.Name.Local == "Endereco" && enderecoDepth > 0 {
				enderecoDepth--
			}
		}
	}
	return r, achou
}

func todoTextoConcatenado(doc []byte) string {
	var sb strings.Builder
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if cd, ok := tok.(xml.CharData); ok {
			sb.Write(cd)
		}
	}
	return sb.String()
}
