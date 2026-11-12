package assinador

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const senhaPfxDeTeste = "teste123" // senha do PFX SINTÉTICO de testdata/, não é segredo real

// TestNenhumCertificadoDeTestdataEhICPBrasil é o GUARD: testdata/ só pode
// conter certificados SINTÉTICOS. Um certificado real (emissor ICP-Brasil)
// não pode entrar no repositório — este teste reprova se algum entrar.
func TestNenhumCertificadoDeTestdataEhICPBrasil(t *testing.T) {
	certsDir := filepath.Join(testdata, "certs")
	entradas, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("lendo %s: %v", certsDir, err)
	}

	verificados := 0
	for _, e := range entradas {
		if e.IsDir() {
			continue
		}
		caminho := filepath.Join(certsDir, e.Name())
		conteudo, err := os.ReadFile(caminho)
		if err != nil {
			t.Fatalf("lendo %s: %v", caminho, err)
		}

		switch {
		case strings.HasSuffix(e.Name(), ".pem") && strings.Contains(e.Name(), "crt"):
			bloco, _ := pem.Decode(conteudo)
			if bloco == nil {
				continue // não é o certificado (ex.: teste.key.pem)
			}
			cert, err := x509.ParseCertificate(bloco.Bytes)
			if err != nil {
				t.Fatalf("parseando certificado %s: %v", caminho, err)
			}
			verificarNaoEhICPBrasil(t, caminho, cert)
			verificados++

		case strings.HasSuffix(e.Name(), ".der"):
			cert, err := x509.ParseCertificate(conteudo)
			if err != nil {
				t.Fatalf("parseando certificado %s: %v", caminho, err)
			}
			verificarNaoEhICPBrasil(t, caminho, cert)
			verificados++

		case strings.HasSuffix(e.Name(), ".pfx") || strings.HasSuffix(e.Name(), ".p12"):
			_, cert, err := pkcs12.Decode(conteudo, senhaPfxDeTeste)
			if err != nil {
				t.Fatalf("decodificando PFX %s: %v", caminho, err)
			}
			verificarNaoEhICPBrasil(t, caminho, cert)
			verificados++
		}
	}

	if verificados == 0 {
		t.Fatal("guard não verificou nenhum certificado — testdata/certs vazio ou nomes mudaram")
	}
}

func verificarNaoEhICPBrasil(t *testing.T, caminho string, cert *x509.Certificate) {
	t.Helper()
	issuer := cert.Issuer.String()
	if strings.Contains(strings.ToUpper(issuer), "ICP-BRASIL") {
		t.Errorf("🔴 %s: emissor contém ICP-Brasil (%q) — parece certificado REAL, não sintético. NÃO COMMITAR.", caminho, issuer)
	}
}
