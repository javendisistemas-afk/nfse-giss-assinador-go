package assinador

import (
	"crypto/rsa"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestAssinarComPFXNosTresFormatos confirma que os 3 PFX sintéticos (3DES
// legado, RC2 legado, AES/PBES2 moderno — golang.org/x/crypto/pkcs12 não
// abre o terceiro, medido em 30/09/2026) abrem via software.sslmate.com/src/go-pkcs12
// e produzem a MESMA assinatura do par PEM, já que é o mesmo par de chaves.
func TestAssinarComPFXNosTresFormatos(t *testing.T) {
	senha := "teste123"
	arquivos := []string{
		"certs/teste-legado-3des.pfx",
		"certs/teste-legado-rc2.pfx",
		"certs/teste-moderno-aes.pfx",
	}

	entrada := lerArquivoTeste(t, "xml/lote-sem-assinatura-a.xml")
	esperado := lerArquivoTeste(t, "xml/lote-assinado-a.xml")

	for _, arq := range arquivos {
		t.Run(arq, func(t *testing.T) {
			chaveIface, cert, err := pkcs12.Decode(lerArquivoTeste(t, arq), senha)
			if err != nil {
				t.Fatalf("pkcs12.Decode(%s): %v", arq, err)
			}
			chave, ok := chaveIface.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("%s: chave não é RSA: %T", arq, chaveIface)
			}

			saida, err := Assinar(entrada, []string{"rps1", "rps2", "lote1"}, chave, cert, PrefixoDS, C14NInclusiva)
			if err != nil {
				t.Fatalf("Assinar com %s: %v", arq, err)
			}
			if string(saida) != string(esperado) {
				t.Fatalf("%s: saída não bate com o golden (mesma chave/certificado dos vetores PEM)", arq)
			}
		})
	}
}
