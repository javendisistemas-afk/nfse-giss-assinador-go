package assinador

import (
	"errors"
	"testing"
)

// TestAssinarRejeitaConstrucoesNaoSuportadas exige o erro tipado
// ErrConstrucaoNaoSuportada exatamente nos 2 vetores de testdata/c14n/ em
// que o C14N10Rec do goxmldsig diverge do XML C14N 1.0 (medido em
// 30/09/2026). Assinar NUNCA pode devolver uma assinatura nesses casos.
func TestAssinarRejeitaConstrucoesNaoSuportadas(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)

	casos := []struct {
		nome    string
		entrada string
	}{
		{"atributo prefixado desordenado", "c14n/02-atributos-ordenados.entrada.xml"},
		{"xmlns padrão sobreposto", "c14n/08-default-sobreposto.entrada.xml"},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			entrada := lerArquivoTeste(t, c.entrada)

			_, err := Assinar(entrada, []string{"alvo"}, chave, cert, PrefixoDS, C14NInclusiva)
			if err == nil {
				t.Fatalf("esperava ErrConstrucaoNaoSuportada, Assinar não devolveu erro nenhum")
			}
			var alvo *ErrConstrucaoNaoSuportada
			if !errors.As(err, &alvo) {
				t.Fatalf("esperava *ErrConstrucaoNaoSuportada, veio: %v", err)
			}
			t.Logf("erro (esperado): %v", alvo)
		})
	}
}

// TestGuardNaoAcusaOsOutros8Vetores é o controle: dos 10 vetores de
// testdata/c14n/, os outros 8 (que o goxmldsig reproduz corretamente) NÃO
// podem ser rejeitados pelo guard — senão ele também bloquearia construções
// válidas.
func TestGuardNaoAcusaOsOutros8Vetores(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)

	nomes := []string{
		"01-heranca-e-declaracao-nao-usada",
		"03-escape-texto",
		"04-escape-atributo",
		"05-vazio-expande",
		"06-utf8-sem-entidade",
		"07-ns-redundante-removido",
		"09-cdata-e-charref",
		"10-espacos-preservados",
	}

	for _, nome := range nomes {
		t.Run(nome, func(t *testing.T) {
			entrada := lerArquivoTeste(t, "c14n/"+nome+".entrada.xml")
			_, err := Assinar(entrada, []string{"alvo"}, chave, cert, PrefixoDS, C14NInclusiva)
			var naoSuportada *ErrConstrucaoNaoSuportada
			if errors.As(err, &naoSuportada) {
				t.Fatalf("guard acusou um vetor que a lib reproduz corretamente: %v", naoSuportada)
			}
			// outros erros (ex.: xmlns:ds ausente) não são o que este teste mede.
		})
	}
}
