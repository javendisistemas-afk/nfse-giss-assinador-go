package transmissor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type certComChave struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func gerarCertTeste(t *testing.T, cn string, ehCA bool, emissor *certComChave, notBefore, notAfter time.Time) certComChave {
	t.Helper()
	chave, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gerando chave de %s: %v", cn, err)
	}
	modelo := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:                pkix.Name{CommonName: cn},
		NotBefore:              notBefore,
		NotAfter:               notAfter,
		KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                   ehCA,
	}

	emissorCert := modelo
	emissorChave := chave
	if emissor != nil {
		emissorCert = emissor.cert
		emissorChave = emissor.key
	}

	der, err := x509.CreateCertificate(rand.Reader, modelo, emissorCert, &chave.PublicKey, emissorChave)
	if err != nil {
		t.Fatalf("criando certificado de %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parseando certificado de %s: %v", cn, err)
	}
	return certComChave{cert: cert, key: chave}
}

// TestCarregarCertificadoPFX_CadeiaAcheFolhaPelaChaveNaoPelaOrdem é a prova
// central do item 1 do desenho do PO: monta um PFX SINTÉTICO com 3
// certificados (raiz, intermediária, folha) onde a folha NÃO é o primeiro
// bag — Encode() sempre bota o parâmetro "certificate" primeiro, então aqui
// esse parâmetro é a INTERMEDIÁRIA de propósito, com a folha e a raiz
// dentro de caCerts. Se o código confiasse na ordem (DecodeChain simples),
// escolheria a intermediária como "folha" — errado.
func TestCarregarCertificadoPFX_CadeiaAcheFolhaPelaChaveNaoPelaOrdem(t *testing.T) {
	agora := time.Now()
	raiz := gerarCertTeste(t, "AC RAIZ TESTE", true, nil, agora.Add(-24*time.Hour), agora.Add(10*365*24*time.Hour))
	intermediaria := gerarCertTeste(t, "AC INTERMEDIARIA TESTE", true, &raiz, agora.Add(-24*time.Hour), agora.Add(5*365*24*time.Hour))
	folha := gerarCertTeste(t, "FOLHA TESTE", false, &intermediaria, agora.Add(-24*time.Hour), agora.Add(365*24*time.Hour))

	const senha = "teste-cadeia-123"
	// bag order escrambled DE PROPÓSITO: "certificate" = intermediária (NÃO
	// é a folha); folha e raiz vão dentro de caCerts.
	pfxBytes, err := pkcs12.Encode(rand.Reader, folha.key, intermediaria.cert, []*x509.Certificate{folha.cert, raiz.cert}, senha)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	caminho := t.TempDir() + "/cadeia-escrambled.pfx"
	if err := os.WriteFile(caminho, pfxBytes, 0o644); err != nil {
		t.Fatalf("escrevendo PFX de teste: %v", err)
	}

	certTLS, err := CarregarCertificadoPFX(caminho, senha)
	if err != nil {
		t.Fatalf("CarregarCertificadoPFX: %v", err)
	}

	if certTLS.Leaf == nil {
		t.Fatal("Leaf veio nil")
	}
	if certTLS.Leaf.Subject.CommonName != "FOLHA TESTE" {
		t.Fatalf("Leaf escolhido = %q, esperava %q (a lib teria escolhido %q se confiasse na ordem)",
			certTLS.Leaf.Subject.CommonName, "FOLHA TESTE", "AC INTERMEDIARIA TESTE")
	}
	if !certTLS.Leaf.PublicKey.(*rsa.PublicKey).Equal(&folha.key.PublicKey) {
		t.Fatal("Leaf.PublicKey não corresponde à chave privada da folha real")
	}

	// mTLS: folha PRIMEIRO, cadeia completa presente (folha + intermediária
	// + raiz), nessa ordem — ver item 2 do desenho.
	if len(certTLS.Certificate) != 3 {
		t.Fatalf("esperava 3 certificados na cadeia mTLS (folha+intermediária+raiz), achou %d", len(certTLS.Certificate))
	}
	primeiroCert, err := x509.ParseCertificate(certTLS.Certificate[0])
	if err != nil {
		t.Fatalf("parseando certTLS.Certificate[0]: %v", err)
	}
	if primeiroCert.Subject.CommonName != "FOLHA TESTE" {
		t.Fatalf("certTLS.Certificate[0] = %q, esperava a folha primeiro", primeiroCert.Subject.CommonName)
	}

	// o resto da cadeia (não a folha) contém a intermediária e a raiz —
	// in qualquer ordem relativa entre si, mas nunca a folha de novo.
	nomesResto := map[string]bool{}
	for _, raw := range certTLS.Certificate[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("parseando cert do resto da cadeia: %v", err)
		}
		nomesResto[c.Subject.CommonName] = true
	}
	if !nomesResto["AC INTERMEDIARIA TESTE"] || !nomesResto["AC RAIZ TESTE"] {
		t.Fatalf("cadeia incompleta: %v", nomesResto)
	}
}

// TestCarregarCertificadoPFX_FolhaVencidaDaErroAntesDeQualquerRede é o item
// 4 do desenho: certificado com NotAfter no passado tem de errar, com as
// DATAS no erro (nunca dado do titular).
func TestCarregarCertificadoPFX_FolhaVencidaDaErroAntesDeQualquerRede(t *testing.T) {
	agora := time.Now()
	vencida := gerarCertTeste(t, "FOLHA VENCIDA TESTE", false, nil, agora.Add(-2*365*24*time.Hour), agora.Add(-24*time.Hour))

	const senha = "teste-vencida-123"
	pfxBytes, err := pkcs12.Encode(rand.Reader, vencida.key, vencida.cert, nil, senha)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	caminho := t.TempDir() + "/vencida.pfx"
	if err := os.WriteFile(caminho, pfxBytes, 0o644); err != nil {
		t.Fatalf("escrevendo PFX de teste: %v", err)
	}

	_, err = CarregarCertificadoPFX(caminho, senha)
	if err == nil {
		t.Fatal("esperava erro para certificado vencido, veio nil")
	}
	if !strings.Contains(err.Error(), "vencido") {
		t.Fatalf("erro não menciona 'vencido': %v", err)
	}
	if strings.Contains(err.Error(), "FOLHA VENCIDA TESTE") {
		t.Fatalf("erro vazou o CommonName do titular: %v", err)
	}
}
