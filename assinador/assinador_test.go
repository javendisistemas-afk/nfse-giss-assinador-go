package assinador

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

const testdata = "../testdata"

func lerArquivoTeste(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdata, rel))
	if err != nil {
		t.Fatalf("lendo %s: %v", rel, err)
	}
	return b
}

func carregarChaveECertificadoDeTeste(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	blocoChave, _ := pem.Decode(lerArquivoTeste(t, "certs/teste.key.pem"))
	if blocoChave == nil {
		t.Fatal("PEM da chave de teste não decodificou")
	}
	chaveIface, err := x509.ParsePKCS8PrivateKey(blocoChave.Bytes)
	if err != nil {
		t.Fatalf("parseando chave de teste: %v", err)
	}
	chave, ok := chaveIface.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("chave de teste não é RSA: %T", chaveIface)
	}

	blocoCert, _ := pem.Decode(lerArquivoTeste(t, "certs/teste.crt.pem"))
	if blocoCert == nil {
		t.Fatal("PEM do certificado de teste não decodificou")
	}
	cert, err := x509.ParseCertificate(blocoCert.Bytes)
	if err != nil {
		t.Fatalf("parseando certificado de teste: %v", err)
	}

	return chave, cert
}

// TestAssinarReproduzOsVetoresDourados assina o XML SEM assinatura de cada
// variante (A e B) e compara, byte a byte, com o XML assinado esperado em
// testdata/xml/lote-assinado-{a,b}.xml — a prova central desta fatia.
func TestAssinarReproduzOsVetoresDourados(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)

	casos := []struct {
		variante      string
		ns            Namespace
		semAssinatura string
		assinado      string
	}{
		{"A", PrefixoDS, "xml/lote-sem-assinatura-a.xml", "xml/lote-assinado-a.xml"},
		{"B", PadraoNaSignature, "xml/lote-sem-assinatura-b.xml", "xml/lote-assinado-b.xml"},
	}

	for _, c := range casos {
		t.Run(c.variante, func(t *testing.T) {
			entrada := lerArquivoTeste(t, c.semAssinatura)
			esperado := lerArquivoTeste(t, c.assinado)

			saida, err := Assinar(entrada, []string{"rps1", "rps2", "lote1"}, chave, cert, c.ns, C14NInclusiva)
			if err != nil {
				t.Fatalf("Assinar: %v", err)
			}

			if string(saida) != string(esperado) {
				n := len(esperado)
				if len(saida) < n {
					n = len(saida)
				}
				i := 0
				for i < n && esperado[i] == saida[i] {
					i++
				}
				ini := i - 60
				if ini < 0 {
					ini = 0
				}
				fimE := i + 60
				if fimE > len(esperado) {
					fimE = len(esperado)
				}
				fimS := i + 60
				if fimS > len(saida) {
					fimS = len(saida)
				}
				t.Fatalf("saída diverge do golden no byte %d (esperado=%dB, saida=%dB)\n  esperado: ...%s...\n  saida   : ...%s...",
					i, len(esperado), len(saida), esperado[ini:fimE], saida[ini:fimS])
			}
		})
	}
}

// TestAssinarIdInexistenteFalha garante erro claro (e não pânico) quando o
// Id pedido não existe no XML.
func TestAssinarIdInexistenteFalha(t *testing.T) {
	chave, cert := carregarChaveECertificadoDeTeste(t)
	entrada := lerArquivoTeste(t, "xml/lote-sem-assinatura-a.xml")

	_, err := Assinar(entrada, []string{"nao-existe"}, chave, cert, PrefixoDS, C14NInclusiva)
	if err == nil {
		t.Fatal("esperava erro para Id inexistente, veio nil")
	}
}
