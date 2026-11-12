package assinador

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// AssinarRpsInterno (F4.21, variante em teste; não substitui Assinar): ids "rps_" apontam para o
// Rps INTERNO (tcInfRps, Id nele); a Signature vai como irmã de InfDeclaracaoPrestacaoServico,
// posição que o XSD permite (tcInfDeclaracaoPrestacaoServico não aceita Signature). Ids de lote
// seguem o caminho normal.
func AssinarRpsInterno(xmlEntrada []byte, ids []string, chave *rsa.PrivateKey, certificado *x509.Certificate, ns Namespace, c14n C14N) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlEntrada); err != nil {
		return nil, fmt.Errorf("assinador: XML de entrada inválido: %w", err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("assinador: XML de entrada sem elemento raiz")
	}
	canon := canonicalizadorDe(c14n)
	certB64 := base64.StdEncoding.EncodeToString(certificado.Raw)
	for _, id := range ids {
		if err := assinarUmNo(doc, canon, id, strings.HasPrefix(id, "rps_"), chave, certB64, ns, c14n); err != nil {
			return nil, err
		}
	}
	saida, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("assinador: falha ao serializar XML assinado: %w", err)
	}
	return saida, nil
}
