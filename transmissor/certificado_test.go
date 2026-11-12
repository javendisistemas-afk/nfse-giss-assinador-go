package transmissor

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestCarregarCertificadoPFX_ComCertificadoSintetico(t *testing.T) {
	caminho := filepath.Join("..", "testdata", "certs", "teste-moderno-aes.pfx")
	cert, err := CarregarCertificadoPFX(caminho, "teste123")
	if err != nil {
		t.Fatalf("CarregarCertificadoPFX: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("cert.Leaf veio nil")
	}
	if cert.Leaf.Subject.CommonName == "" {
		t.Fatal("CommonName vazio")
	}
}

func TestCarregarCertificadoPFX_SenhaErradaDaErro(t *testing.T) {
	caminho := filepath.Join("..", "testdata", "certs", "teste-moderno-aes.pfx")
	_, err := CarregarCertificadoPFX(caminho, "senha-errada-de-proposito")
	if err == nil {
		t.Fatal("esperava erro com senha errada, veio nil")
	}
}

func TestCarregarCertificadoPFX_ArquivoInexistenteDaErro(t *testing.T) {
	_, err := CarregarCertificadoPFX(filepath.Join(os.TempDir(), "zz-nao-existe.pfx"), "qualquer")
	if err == nil {
		t.Fatal("esperava erro para arquivo inexistente, veio nil")
	}
}

// TestClienteMTLS_TLSConfigNaoPulaVerificacao inspeciona o *tls.Config
// MONTADO (não só o texto-fonte — complementa o guard de fonte em
// guard_test.go): InsecureSkipVerify tem de ser false e o certificado
// cliente tem de estar presente.
func TestClienteMTLS_TLSConfigNaoPulaVerificacao(t *testing.T) {
	caminho := filepath.Join("..", "testdata", "certs", "teste-moderno-aes.pfx")
	cert, err := CarregarCertificadoPFX(caminho, "teste123")
	if err != nil {
		t.Fatalf("CarregarCertificadoPFX: %v", err)
	}
	cliente := ClienteMTLS(cert)
	transport, ok := cliente.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("cliente sem *http.Transport com TLSClientConfig")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify=true — nunca pode acontecer")
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("esperava 1 certificado no TLSClientConfig, achou %d", len(transport.TLSClientConfig.Certificates))
	}
}
