package transmissor

import "testing"

// TestEndpointHomologacaoValorExato ancora o valor LITERAL do endpoint — é o
// guard de FONTE (CLAUDE.md): só o nome da constante não prova nada, quem
// prova é o valor. Se alguém trocar a URL (produção, typo, host diferente),
// este teste cai.
func TestEndpointHomologacaoValorExato(t *testing.T) {
	const esperado = "https://v2-ws-homologacao.giss.com.br/service-ws/nf/nfse-ws"
	if EndpointHomologacao != esperado {
		t.Fatalf("EndpointHomologacao mudou: %q (esperado %q)", EndpointHomologacao, esperado)
	}
}

// TestValidarEndpointSoAceitaHomologacao é o guard de COMPORTAMENTO: prova
// que validarEndpoint rejeita produção, typo de protocolo, host parecido e
// caminho trocado — não só que aceita o certo.
func TestValidarEndpointSoAceitaHomologacao(t *testing.T) {
	if err := validarEndpoint(EndpointHomologacao); err != nil {
		t.Fatalf("endpoint de homologação foi rejeitado: %v", err)
	}

	rejeitados := []string{
		"https://v2-ws.giss.com.br/service-ws/nf/nfse-ws",                              // produção (sem "-homologacao")
		"http://v2-ws-homologacao.giss.com.br/service-ws/nf/nfse-ws",                   // http, não https
		"https://v2-ws-homologacao.giss.com.br.attacker.example/service-ws/nf/nfse-ws", // host disfarçado
		"https://v2-ws-homologacao.giss.com.br/service-ws/nf/outro",                    // caminho trocado
		"",
	}
	for _, url := range rejeitados {
		if err := validarEndpoint(url); err == nil {
			t.Fatalf("validarEndpoint aceitou um host fora do permitido: %q", url)
		}
	}
}

// TestValidarEndpointProducaoAceitaHttpsEReprovaOResto — F7.12: esta lib é pública e atende
// qualquer município GISS, então validarEndpointProducao não conhece mais um host específico (quem
// chama EnviarProducao decide qual é o endpoint real, e faz a allowlist por valor exato do seu
// lado). O que resta aqui pra provar é a checagem genérica: aceita https não-vazio, reprova http e
// vazio.
func TestValidarEndpointProducaoAceitaHttpsEReprovaOResto(t *testing.T) {
	aceitos := []string{
		"https://ws-exemplo-municipio.giss.com.br/service-ws/nf/nfse-ws",
		"https://outro-exemplo.com.br/caminho/qualquer",
	}
	for _, url := range aceitos {
		if err := validarEndpointProducao(url); err != nil {
			t.Fatalf("validarEndpointProducao rejeitou um https válido: %q: %v", url, err)
		}
	}

	rejeitados := []string{
		"http://ws-exemplo-municipio.giss.com.br/service-ws/nf/nfse-ws", // http, não https
		"",
	}
	for _, url := range rejeitados {
		if err := validarEndpointProducao(url); err == nil {
			t.Fatalf("validarEndpointProducao aceitou um endpoint inválido: %q", url)
		}
	}
}

// TestPadraoNuncaAlcancaProducao prova que o caminho padrão (validarEndpoint, usado por Enviar)
// reprova qualquer endpoint https diferente de homologação: sem -producao-confirmado, nada chega
// a produção, seja ela qual for.
func TestPadraoNuncaAlcancaProducao(t *testing.T) {
	if err := validarEndpoint("https://ws-exemplo-municipio.giss.com.br/service-ws/nf/nfse-ws"); err == nil {
		t.Fatal("validarEndpoint (caminho padrão) aceitou um endpoint que não é o de homologação")
	}
}
