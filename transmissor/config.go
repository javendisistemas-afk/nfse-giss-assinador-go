package transmissor

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config é o config-homologacao.json compartilhado entre este agente (só lê
// o bloco Certificado) e o gerador temporário do emissor (só lê o bloco
// Prestador). Nenhum campo de segredo mora aqui — nem o .pfx, nem a senha:
// só o CAMINHO do .pfx. A senha vem do Gerenciador de Credenciais — o
// nome-alvo da credencial é decisão de quem CHAMA esta lib (F7.12: esta lib
// é pública, não deve fixar nenhum nome-alvo específico de cliente).
type Config struct {
	Certificado ConfigCertificado `json:"certificado"`
	Prestador   ConfigPrestador   `json:"prestador"`
}

type ConfigCertificado struct {
	CaminhoPFX string `json:"caminho_pfx"`
}

type ConfigEndereco struct {
	Logradouro          string `json:"logradouro"`
	Numero              string `json:"numero"`
	Complemento         string `json:"complemento"`
	Bairro              string `json:"bairro"`
	CodigoMunicipioIBGE string `json:"codigo_municipio_ibge"`
	UF                  string `json:"uf"`
	CEP                 string `json:"cep"`
}

// ConfigPrestador — os campos que o GERADOR de referência precisa para montar
// NfseConfigEmissor (backend/nfse_rps_xml.go). Dado real do prestador: só
// existe na cópia REAL do config-homologacao.json de cada instalação, nunca
// no exemplo nem em log/commit.
type ConfigPrestador struct {
	CNPJ                      string         `json:"cnpj"`
	InscricaoMunicipal        string         `json:"inscricao_municipal"`
	RazaoSocial               string         `json:"razao_social"`
	Endereco                  ConfigEndereco `json:"endereco"`
	OptanteSimples            bool           `json:"optante_simples_nacional"`
	IncentivoFiscal           bool           `json:"incentivo_fiscal"`
	AliquotaISS               string         `json:"aliquota_iss"`
	AliquotaFormato           string         `json:"aliquota_formato"`
	ItemListaServico          string         `json:"item_lista_servico"`
	CNAE                      string         `json:"cnae"`
	CodigoTributacaoMunicipio string         `json:"codigo_tributacao_municipio"`
	CodigoNbs                 string         `json:"codigo_nbs"`
	CodigoPais                string         `json:"codigo_pais"`
	ExigibilidadeISS          string         `json:"exigibilidade_iss"`
	MunicipioIncidencia       string         `json:"municipio_incidencia"`
	// CNCComplementar — "há registro complementar do contribuinte (CNPJ+IM) no CNC NFS-e do
	// município emissor?" (regra de negócio E0116/E0120/E0124 do Sistema Nacional, achado F7.6g/h:
	// scratchpad/f71_anexo_unzipped/xl/sharedStrings.xml:587-601). NÃO é um dado do cadastro local —
	// é o estado desse município específico no CNC NACIONAL, que hoje só a resposta real do ADN
	// revela (achado medido 09/11/2026, num município de produção real). Default false/omitido:
	// hoje nenhum município do emissor tem esse registro. Mude pra true quando o município se
	// cadastrar no CNC.
	CNCComplementar bool `json:"cnc_complementar"`
	// CIndOp — "código indicador de operação" (TSRTCCodIndOp, tipos-v2_04.xsd:1021-1031, 6
	// dígitos, tabela "código indicador de operação"): bloco IBSCBS, campo diferente de
	// cLocalidadeIncid. F4.15: confirmado "030101" pelo suporte da GISS olhando o protocolo real
	// (3074577) — diverge do que a tabela de correlação (F4.6/F4.7) indica pro item 01.05
	// (INDOP=100501 lá; 030101 é o valor daquela tabela pro item antigo 08.02) — achado
	// registrado, não resolvido; seguindo a orientação direta do suporte, não a tabela genérica.
	CIndOp string `json:"cindop"`
}

// LerConfig lê e decodifica o config-homologacao.json do CAMINHO dado pelo
// chamador (este pacote não decide onde o arquivo está).
func LerConfig(caminho string) (Config, error) {
	b, err := os.ReadFile(caminho)
	if err != nil {
		return Config{}, fmt.Errorf("transmissor: lendo config %s: %w", caminho, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("transmissor: decodificando config %s: %w", caminho, err)
	}
	return cfg, nil
}
