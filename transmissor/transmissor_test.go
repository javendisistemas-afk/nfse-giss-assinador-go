package transmissor

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// TestEnviar_FluxoCompletoComServidorTesteMTLS prova o caminho de rede de
// ponta a ponta (mTLS + headers + corpo) contra um servidor LOCAL — nunca o
// GISS real. Usa montarRequisicao (não Enviar) porque Enviar só aceita
// EndpointHomologacao por desenho (ver endpoint_test.go); aqui o alvo é
// provar que o CLIENTE monta a requisição e faz o handshake mTLS certo.
func TestEnviar_FluxoCompletoComServidorTesteMTLS(t *testing.T) {
	certCliente, err := CarregarCertificadoPFX(filepath.Join("..", "testdata", "certs", "teste-moderno-aes.pfx"), "teste123")
	if err != nil {
		t.Fatalf("CarregarCertificadoPFX: %v", err)
	}

	const respostaFake = `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:GerarNfseResposta xmlns:ns="http://www.giss.com.br/gerar-nfse-resposta-v2_04.xsd"><ListaMensagemRetorno xmlns="http://www.giss.com.br/tipos-v2_04.xsd"><MensagemRetorno><Codigo>E001</Codigo><Mensagem>erro de teste</Mensagem></MensagemRetorno></ListaMensagemRetorno></ns:GerarNfseResposta></soapenv:Body></soapenv:Envelope>`

	var corpoRecebido []byte
	var soapActionRecebido string
	var contentTypeRecebido string
	var peerCertRecebido bool

	servidor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		soapActionRecebido = r.Header.Get("SOAPAction")
		contentTypeRecebido = r.Header.Get("Content-Type")
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerCertRecebido = true
		}
		corpoRecebido, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respostaFake))
	}))
	servidor.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	servidor.StartTLS()
	defer servidor.Close()

	pool := x509.NewCertPool()
	pool.AddCert(servidor.Certificate())

	cliente := ClienteMTLS(certCliente)
	transport := cliente.Transport.(*http.Transport)
	transport.TLSClientConfig.RootCAs = pool // confia no servidor de TESTE (não é InsecureSkipVerify)

	envelopeFake := []byte(`<envelope-de-teste/>`)
	req, err := montarRequisicao(servidor.URL, envelopeFake, SOAPActionGerarNfse)
	if err != nil {
		t.Fatalf("montarRequisicao: %v", err)
	}

	resp, err := cliente.Do(req)
	if err != nil {
		t.Fatalf("cliente.Do: %v", err)
	}
	defer resp.Body.Close()
	corpoResposta, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("lendo corpo da resposta: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, esperava 200", resp.StatusCode)
	}
	if !peerCertRecebido {
		t.Fatal("servidor não recebeu certificado do cliente — mTLS não aconteceu")
	}
	if soapActionRecebido != `"`+SOAPActionGerarNfse+`"` {
		t.Fatalf("SOAPAction = %q, esperava %q", soapActionRecebido, `"`+SOAPActionGerarNfse+`"`)
	}
	if contentTypeRecebido != "text/xml; charset=utf-8" {
		t.Fatalf("Content-Type = %q", contentTypeRecebido)
	}
	if string(corpoRecebido) != string(envelopeFake) {
		t.Fatalf("corpo recebido pelo servidor = %s, esperava %s", corpoRecebido, envelopeFake)
	}
	if string(corpoResposta) != respostaFake {
		t.Fatalf("corpo da resposta não bate")
	}

	resultado, err := InterpretarResposta(corpoResposta)
	if err != nil {
		t.Fatalf("InterpretarResposta: %v", err)
	}
	if resultado.Autorizada {
		t.Fatal("esperava reprovada (ListaMensagemRetorno), veio Autorizada")
	}
	if len(resultado.Mensagens) != 1 || resultado.Mensagens[0].Codigo != "E001" {
		t.Fatalf("mensagens = %+v", resultado.Mensagens)
	}
}
