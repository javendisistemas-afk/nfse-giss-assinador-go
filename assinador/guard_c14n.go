package assinador

import (
	"fmt"

	"github.com/beevik/etree"
)

// ErrConstrucaoNaoSuportada é devolvido quando o alvo a assinar contém uma
// construção de XML em que o C14N10Rec do goxmldsig diverge do XML C14N
// 1.0 (medido em 30/09/2026, fatia F4.2/F4.2b, contra os vetores abstratos
// testdata/c14n/02-atributos-ordenados e testdata/c14n/08-default-sobreposto).
// Assinar nunca produz uma assinatura sobre um destes casos — devolve este
// erro em vez de um DigestValue/SignatureValue potencialmente errado.
type ErrConstrucaoNaoSuportada struct {
	Motivo  string
	Caminho string
}

func (e *ErrConstrucaoNaoSuportada) Error() string {
	return fmt.Sprintf("assinador: construção de XML não suportada pelo C14N desta lib (%s), em %s", e.Motivo, e.Caminho)
}

// verificarConstrucaoSuportada varre o alvo (já anexado ao documento) e
// reprova os 2 casos medidos em que o C14N10Rec do goxmldsig diverge do XML
// C14N 1.0 (xml-c14n-20010315):
//
//  1. um elemento com 2+ atributos de PREFIXOS DE NAMESPACE diferentes — o
//     C14N exige ordená-los pela URI do namespace; a lib preserva a ordem
//     do documento-fonte.
//  2. um elemento que REDECLARA seu próprio xmlns padrão com valor
//     DIFERENTE do herdado de um ancestral — a lib ignora a redeclaração e
//     usa a do ancestral.
//
// ⚠️ F7.2a: estes 2 vetores foram medidos SÓ contra C14N10Rec (inclusiva). Com C14N
// exclusiva (tipo C14N, mesma fatia) este guard continua rodando — por cautela, não foi
// desligado —, mas NINGUÉM mediu se MakeC14N10ExclusiveCanonicalizerWithPrefixList diverge do
// XML C14N exclusivo nestes mesmos 2 casos, nem se diverge em casos DIFERENTES que este guard
// não cobre. Não é garantia pra C14NExclusiva, é só a mesma rede de segurança que já existia,
// sem prova de que seja a rede certa pro canonicalizer novo.
func verificarConstrucaoSuportada(el *etree.Element) error {
	return verificarConstrucaoRecursivo(el, defaultNamespaceHerdado(el.Parent()))
}

func defaultNamespaceHerdado(el *etree.Element) string {
	for el != nil {
		for _, a := range el.Attr {
			if a.Space == "" && a.Key == "xmlns" {
				return a.Value
			}
		}
		el = el.Parent()
	}
	return ""
}

func verificarConstrucaoRecursivo(el *etree.Element, defaultHerdado string) error {
	prefixos := map[string]bool{}
	propriDefault := ""
	temPropriDefault := false

	for _, a := range el.Attr {
		switch {
		case a.Space == "" && a.Key == "xmlns":
			propriDefault = a.Value
			temPropriDefault = true
		case a.Space != "" && a.Space != "xmlns":
			prefixos[a.Space] = true
		}
	}

	if len(prefixos) >= 2 {
		return &ErrConstrucaoNaoSuportada{
			Motivo:  "2+ atributos com prefixo de namespace diferente no mesmo elemento (vetor 02-atributos-ordenados)",
			Caminho: el.GetPath(),
		}
	}

	defaultEfetivo := defaultHerdado
	if temPropriDefault {
		if defaultHerdado != "" && propriDefault != defaultHerdado {
			return &ErrConstrucaoNaoSuportada{
				Motivo:  "xmlns padrão redeclarado difere do herdado do ancestral (vetor 08-default-sobreposto)",
				Caminho: el.GetPath(),
			}
		}
		defaultEfetivo = propriDefault
	}

	for _, filho := range el.ChildElements() {
		if err := verificarConstrucaoRecursivo(filho, defaultEfetivo); err != nil {
			return err
		}
	}
	return nil
}
