package transmissor

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CarregarCertificadoPFX lê e decodifica um .pfx. Caminho e senha já vêm
// prontos do CHAMADOR (config + Gerenciador de Credenciais) — este pacote
// nunca lê o Gerenciador de Credenciais nem decide onde está o arquivo.
//
// Usa DecodeChain (não Decode) porque um .pfx real pode trazer a cadeia
// completa (folha + intermediárias), não só 2 bags — medido contra o
// certificado real desta fatia (F4.3). A folha é achada CONFERINDO a chave
// pública de cada certificado contra a chave privada — nunca por ORDEM dos
// bags (DecodeChain assume "o primeiro é a folha", o que não é garantido).
func CarregarCertificadoPFX(caminhoPFX, senha string) (tls.Certificate, error) {
	bytesPFX, err := os.ReadFile(caminhoPFX)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transmissor: lendo certificado: %w", err)
	}

	chave, certificadoBag, caCerts, err := pkcs12.DecodeChain(bytesPFX, senha)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transmissor: decodificando PFX: %w", err)
	}

	candidatos := append([]*x509.Certificate{certificadoBag}, caCerts...)
	folha, resto, err := acharFolhaPelaChave(chave, candidatos)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := validarValidade(folha); err != nil {
		return tls.Certificate{}, err
	}

	// mTLS: folha PRIMEIRO, depois a cadeia intermediária/raiz — nessa ordem
	// o handshake TLS espera a cadeia do apresentador.
	cadeia := make([][]byte, 0, 1+len(resto))
	cadeia = append(cadeia, folha.Raw)
	for _, c := range resto {
		cadeia = append(cadeia, c.Raw)
	}

	return tls.Certificate{
		Certificate: cadeia,
		PrivateKey:  chave,
		Leaf:        folha,
	}, nil
}

// acharFolhaPelaChave acha, entre `candidatos` (em QUALQUER ordem), o único
// certificado cuja chave pública corresponde a `chave` — essa é a folha. Os
// demais formam a cadeia intermediária/raiz. Para a assinatura XML, só a
// folha é usada (KeyInfo) — a cadeia nunca entra ali, só no mTLS.
func acharFolhaPelaChave(chave crypto.PrivateKey, candidatos []*x509.Certificate) (folha *x509.Certificate, resto []*x509.Certificate, err error) {
	assinante, ok := chave.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("transmissor: chave privada não implementa crypto.Signer (%T)", chave)
	}
	pubDaChave := assinante.Public()

	for _, c := range candidatos {
		if chavesPublicasIguais(c.PublicKey, pubDaChave) {
			if folha != nil {
				return nil, nil, fmt.Errorf("transmissor: mais de um certificado no PFX corresponde à chave privada — PFX ambíguo")
			}
			folha = c
		} else {
			resto = append(resto, c)
		}
	}
	if folha == nil {
		return nil, nil, fmt.Errorf("transmissor: nenhum certificado no PFX corresponde à chave privada")
	}
	return folha, resto, nil
}

func chavesPublicasIguais(a, b crypto.PublicKey) bool {
	type comparavel interface{ Equal(crypto.PublicKey) bool }
	if ca, ok := a.(comparavel); ok {
		return ca.Equal(b)
	}
	return false
}

// validarValidade erra ANTES de qualquer rede se a folha estiver fora da
// janela de validade — só as DATAS no erro, nunca dado do titular.
func validarValidade(folha *x509.Certificate) error {
	agora := time.Now()
	if agora.Before(folha.NotBefore) {
		return fmt.Errorf("transmissor: certificado ainda não é válido (válido a partir de %s, agora é %s)",
			folha.NotBefore.Format(time.RFC3339), agora.Format(time.RFC3339))
	}
	if agora.After(folha.NotAfter) {
		return fmt.Errorf("transmissor: certificado vencido (válido até %s, agora é %s)",
			folha.NotAfter.Format(time.RFC3339), agora.Format(time.RFC3339))
	}
	return nil
}

// ClienteMTLS monta um *http.Client que se autentica com `cert` via mTLS.
// 🔴 Nunca InsecureSkipVerify: o TLS do SERVIDOR é validado contra as raízes
// do sistema, sem exceção — se não validar, a chamada falha, não silencia.
func ClienteMTLS(cert tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}
