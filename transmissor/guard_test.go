package transmissor

import (
	"bytes"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
	"testing"
)

// semComentarios tira todo comentário do código-fonte Go via go/parser (modo
// SEM ParseComments — o comentário nunca entra na AST) e devolve o texto
// reconstruído pelo go/printer. Diferente de tirar "// " por índice de
// string, isto NÃO quebra uma URL "https://..." dentro de um literal — o
// literal é um nó da AST, preservado verbatim; só o COMENTÁRIO some.
// Regra do CLAUDE.md: "guard lê código, então tire os comentários antes de
// buscar" — sem isto, um comentário EXPLICANDO por que algo é proibido
// ("nunca use X") derrubaria o próprio guard que prova a ausência de X.
func semComentarios(t *testing.T, caminho string) string {
	t.Helper()
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, caminho, nil, 0) // 0 = sem ParseComments
	if err != nil {
		t.Fatalf("parseando %s: %v", caminho, err)
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, astFile); err != nil {
		t.Fatalf("reimprimindo %s: %v", caminho, err)
	}
	return buf.String()
}

// TestNenhumInsecureSkipVerifyNoPacote é o guard de FONTE: nenhum arquivo de
// PRODUÇÃO (não-teste) deste pacote pode USAR "InsecureSkipVerify" em
// código. Regra da fatia: "Nenhum InsecureSkipVerify nem desligamento de
// verificação TLS." certificado_test.go É EXCEÇÃO de propósito: ele
// REFERENCIA o campo só para provar, lendo o *tls.Config montado, que ele
// vem false (TestClienteMTLS_TLSConfigNaoPulaVerificacao) — a citação ali é
// a PROVA da ausência, não a presença do problema.
func TestNenhumInsecureSkipVerifyNoPacote(t *testing.T) {
	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entradas {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if strings.Contains(semComentarios(t, e.Name()), "InsecureSkipVerify") {
			t.Fatalf("%s usa InsecureSkipVerify em código — proibido nesta fatia", e.Name())
		}
	}
}

// TestPadraoNaSignatureNaoReferenciado prova, por construção + guard de
// fonte, que o transmissor só pode assinar com PrefixoDS: a variante
// PadraoNaSignature do pacote assinador não é sequer USADA EM CÓDIGO aqui.
func TestPadraoNaSignatureNaoReferenciado(t *testing.T) {
	entradas, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entradas {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if strings.Contains(semComentarios(t, e.Name()), "PadraoNaSignature") {
			t.Fatalf("%s usa PadraoNaSignature em código — só PrefixoDS pode ser usado para envio", e.Name())
		}
	}
}
