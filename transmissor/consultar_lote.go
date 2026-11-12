package transmissor

// consultar_lote.go — F4.11: monta o corpo de ConsultarLoteRps e interpreta sua resposta. Operação
// de CONSULTA (não submete declaração) — por isso NÃO assina: `Signature` é opcional no XSD
// (consultar-lote-rps-envio-v2_04.xsd, minOccurs="0"), diferente de GerarNfse/RecepcionarLoteRps,
// que assinam a declaração como prova de autoria.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// SituacaoLoteRps — tsSituacaoLoteRps (tipos-v2_04.xsd:659, medido): 1 Não Recebido, 2 Não
// Processado, 3 Processado com Erro, 4 Processado com Sucesso.
type SituacaoLoteRps string

const (
	SituacaoLoteNaoRecebido       SituacaoLoteRps = "1"
	SituacaoLoteNaoProcessado     SituacaoLoteRps = "2"
	SituacaoLoteProcessadoComErro SituacaoLoteRps = "3"
	SituacaoLoteProcessadoOK      SituacaoLoteRps = "4"
)

// NotaAutorizada — o que importa de um CompNfse pra quem só quer saber se autorizou (nunca dado
// do prestador/tomador — mesma régua do Resultado do GerarNfse).
type NotaAutorizada struct {
	NumeroNfse        string
	CodigoVerificacao string
}

// ResultadoConsultaLote — a leitura de ConsultarLoteRpsResposta (consultar-lote-rps-resposta-v2_04.xsd,
// medido): Situacao sempre presente; o resto depende dela — 1/2 (ainda processando) não traz mais
// nada: NotasAutorizadas e Mensagens ficam vazios; 4 traz NotasAutorizadas (ListaNfse/CompNfse,
// pode ter mais de uma); 3 traz Mensagens (ListaMensagemRetorno OU ListaMensagemRetornoLote — os
// dois usam o elemento "MensagemRetorno", lidos da MESMA forma aqui; a variante "Lote" tem
// IdentificacaoRps e NÃO tem Correcao, que então fica vazia).
type ResultadoConsultaLote struct {
	Situacao         SituacaoLoteRps
	NotasAutorizadas []NotaAutorizada
	Mensagens        []MensagemRetorno
}

// MontarConsultarLoteRpsEnvio monta o corpo ConsultarLoteRpsEnvio (consultar-lote-rps-envio-v2_04.xsd,
// medido): Prestador (CpfCnpj + InscricaoMunicipal opcional) + Protocolo — SEM NumeroLote, que o
// XSD não pede aqui. `Prestador`/`Protocolo` são locais ao schema do ENVIO (prefixo p:, mesmo
// padrão do `LoteRps` raiz em EnviarLoteRpsEnvio); `CpfCnpj`/`Cnpj`/`InscricaoMunicipal` são do
// tipo tipos:tcIdentificacaoPessoaEmpresa (prefixo p1:, mesmo padrão já usado no Prestador do
// LoteRps). CNPJ sempre (nunca CPF — o prestador de NFS-e aqui é sempre pessoa jurídica).
func MontarConsultarLoteRpsEnvio(cnpj, inscricaoMunicipal, protocolo string) []byte {
	var b bytes.Buffer
	b.WriteString(`<p:ConsultarLoteRpsEnvio xmlns:p="http://www.giss.com.br/consultar-lote-rps-envio-v2_04.xsd" xmlns:p1="http://www.giss.com.br/tipos-v2_04.xsd">`)
	b.WriteString(`<p:Prestador><p1:CpfCnpj><p1:Cnpj>`)
	xml.EscapeText(&b, []byte(cnpj))
	b.WriteString(`</p1:Cnpj></p1:CpfCnpj>`)
	if inscricaoMunicipal != "" {
		b.WriteString(`<p1:InscricaoMunicipal>`)
		xml.EscapeText(&b, []byte(inscricaoMunicipal))
		b.WriteString(`</p1:InscricaoMunicipal>`)
	}
	b.WriteString(`</p:Prestador><p:Protocolo>`)
	xml.EscapeText(&b, []byte(protocolo))
	b.WriteString(`</p:Protocolo></p:ConsultarLoteRpsEnvio>`)
	return b.Bytes()
}

// InterpretarRespostaConsultarLoteRps lê a resposta bruta de ConsultarLoteRps. Mesma cadeia de
// tentativas do InterpretarResposta (outputXML primeiro, depois direto, depois texto embutido) —
// ver comentário de transmissor.InterpretarResposta pra por quê.
func InterpretarRespostaConsultarLoteRps(respostaBruta []byte) (*ResultadoConsultaLote, error) {
	if outputXML, err := extrairTextoDeElemento(respostaBruta, "outputXML"); err == nil {
		if r, err2 := extrairConsultaLoteResultado(outputXML); err2 == nil {
			return r, nil
		}
	}

	if r, err := extrairConsultaLoteResultado(respostaBruta); err == nil {
		return r, nil
	}

	texto := strings.TrimSpace(todoTextoConcatenado(respostaBruta))
	if strings.HasPrefix(texto, "<") {
		if r, err := extrairConsultaLoteResultado([]byte(texto)); err == nil {
			return r, nil
		}
	}

	return nil, fmt.Errorf("transmissor: elemento Situacao não encontrado na resposta de ConsultarLoteRps (nem em outputXML, nem direto, nem em texto embutido)")
}

// extrairConsultaLoteResultado — F4.40 (achado em produção, 22/10/2026, RPS 296): esta função
// pegou <Numero>890</Numero> (o NÚMERO DA CASA do endereço do tomador) como NumeroNfse, em vez de
// <Numero>296</Numero> (o número da nota) — confirmado contra o portal da prefeitura.
//
// 🔑 A CAUSA: medido na estrutura real de um CompNfse autorizado (290.xml) —
//
//	CompNfse > Nfse > InfNfse > Numero                                            (CORRETO)
//	CompNfse > Nfse > InfNfse > PrestadorServico > Endereco > Numero              (casa do prestador)
//	CompNfse > Nfse > InfNfse > DeclaracaoPrestacaoServico > ... > TomadorServico > Endereco > Numero (casa do tomador)
//
// O scanner só checava `dentroCompNfse` — qualquer um dos TRÊS <Numero> dentro de um CompNfse
// sobrescrevia notaAtual.NumeroNfse, e como são lidos em ORDEM DE DOCUMENTO, o ÚLTIMO (o endereço
// do tomador, que vem depois do prestador no XSD) ganhava. CodigoVerificacao não tem esse
// problema (só aparece uma vez, dentro de InfNfse) — por isso saiu certo.
//
// 🔧 A CORREÇÃO: enderecoDepth (CONTADOR, não bool — Endereco aparece aninhado em Endereco no
// próprio XSD, tcEndereco embrulhando um filho de mesmo nome; um bool viraria false no primeiro
// `</Endereco>` quando ainda se está no de fora). Numero/CodigoVerificacao só são aceitos com
// enderecoDepth == 0 — fora de QUALQUER bloco de endereço, onde só o Numero/CodigoVerificacao da
// NFS-e em si podem aparecer. `notaAtual.NumeroNfse == ""` como segunda trava: aceita só a
// PRIMEIRA ocorrência válida, defesa extra caso uma variante futura do XSD tenha mais de uma.
func extrairConsultaLoteResultado(doc []byte) (*ResultadoConsultaLote, error) {
	r := &ResultadoConsultaLote{}
	situacaoAchada := false
	dentroCompNfse := false
	enderecoDepth := 0
	var notaAtual NotaAutorizada

	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Situacao":
				var v string
				if dec.DecodeElement(&v, &t) == nil {
					r.Situacao = SituacaoLoteRps(strings.TrimSpace(v))
					situacaoAchada = true
				}
			case "CompNfse":
				dentroCompNfse = true
				notaAtual = NotaAutorizada{}
			case "Endereco":
				enderecoDepth++
			case "Numero":
				if dentroCompNfse && enderecoDepth == 0 && notaAtual.NumeroNfse == "" {
					var v string
					if dec.DecodeElement(&v, &t) == nil && v != "" {
						notaAtual.NumeroNfse = v
					}
				}
			case "CodigoVerificacao":
				if dentroCompNfse && enderecoDepth == 0 {
					var v string
					if dec.DecodeElement(&v, &t) == nil {
						notaAtual.CodigoVerificacao = v
					}
				}
			case "MensagemRetorno":
				// cobre tcMensagemRetorno (Codigo/Mensagem/Correcao) E tcMensagemRetornoLote
				// (IdentificacaoRps/Codigo/Mensagem, sem Correcao) — campos que a outra variante
				// não tem ficam vazios, sem erro (encoding/xml ignora o que não casa).
				var m struct {
					Codigo   string
					Mensagem string
					Correcao string
				}
				if dec.DecodeElement(&m, &t) == nil {
					r.Mensagens = append(r.Mensagens, MensagemRetorno(m))
				}
			}
		case xml.EndElement:
			if t.Name.Local == "Endereco" && enderecoDepth > 0 {
				enderecoDepth--
			}
			if t.Name.Local == "CompNfse" {
				if notaAtual.NumeroNfse != "" || notaAtual.CodigoVerificacao != "" {
					r.NotasAutorizadas = append(r.NotasAutorizadas, notaAtual)
				}
				dentroCompNfse = false
				enderecoDepth = 0 // defesa: um Endereco malformado/sem fechamento não vaza pro próximo CompNfse
			}
		}
	}

	if !situacaoAchada {
		return nil, fmt.Errorf("transmissor: elemento Situacao não encontrado")
	}
	return r, nil
}
