#!/usr/bin/env python3
"""
Gera os vetores de teste do assinador XMLDSig (GISS 2.04/ABRASF).

TUDO AQUI E DE TESTE. A chave e o certificado sao descartaveis, gerados
para este pacote. NUNCA use nada disto em producao e NUNCA misture com o
certificado real da empresa.

Referencia: lxml/libxml2 (C14N) + cryptography/OpenSSL (RSA-SHA1).
Ela e independente do assinador em Go que sera escrito.

Regras seguidas (Manual GISS V1.7, tabela XS01-XS21, e XSD 2.04):
  - CanonicalizationMethod: xml-c14n-20010315 (inclusivo, sem comentarios)
  - SignatureMethod: rsa-sha1 ; DigestMethod: sha1
  - Transforms: enveloped-signature e xml-c14n-20010315
  - KeyInfo: so X509Data/X509Certificate
  - Reference URI="#Id"
  - XML compacto (sem espacos/quebras entre tags), UTF-8
  - Assina cada RPS (Signature irma de InfDeclaracaoPrestacaoServico, dentro
    de Rps) e depois o lote (Signature filha da raiz, depois de LoteRps)
"""
import base64, hashlib, json, os, subprocess, sys, datetime
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

AQUI = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(AQUI, "pacote")
DS = "http://www.w3.org/2000/09/xmldsig#"
C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
SENHA_PFX = "teste123"


def esc(p):
    return os.path.join(OUT, p)


def gravar(p, dados):
    os.makedirs(os.path.dirname(esc(p)), exist_ok=True)
    with open(esc(p), "wb") as f:
        f.write(dados if isinstance(dados, bytes) else dados.encode("utf-8"))


# ----------------------------------------------------------------- certificados
def gerar_certificados():
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nome = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EMPRESA TESTE DESCARTAVEL"),
        x509.NameAttribute(NameOID.COMMON_NAME, "EMPRESA TESTE LTDA:11222333000181"),
    ])
    ini = datetime.datetime(2026, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nome).issuer_name(nome)
        .public_key(chave.public_key())
        .serial_number(0x5A17E57)
        .not_valid_before(ini).not_valid_after(ini + datetime.timedelta(days=3650))
        .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(chave, hashes.SHA256())
    )
    key_pem = chave.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    gravar("certs/teste.key.pem", key_pem)
    gravar("certs/teste.crt.pem", cert_pem)
    gravar("certs/teste.crt.der", cert.public_bytes(serialization.Encoding.DER))

    # PFX em tres formatos, para provar que o leitor de PFX do Go aguenta
    # os certificados reais (que costumam ser 3DES/RC2 antigos OU AES novos).
    base = ["openssl", "pkcs12", "-export", "-inkey", esc("certs/teste.key.pem"),
            "-in", esc("certs/teste.crt.pem"), "-passout", "pass:" + SENHA_PFX,
            "-name", "teste"]
    variantes = {
        "teste-legado-3des.pfx": ["-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1"],
        "teste-moderno-aes.pfx": [],  # padrao do OpenSSL 3: PBES2 + AES-256-CBC + HMAC-SHA256
        "teste-legado-rc2.pfx": ["-legacy", "-certpbe", "PBE-SHA1-RC2-40", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1"],
    }
    feitos = []
    for arq, extra in variantes.items():
        r = subprocess.run(base + extra + ["-out", esc("certs/" + arq)], capture_output=True, text=True)
        if r.returncode == 0:
            feitos.append(arq)
        else:
            print("  (PFX", arq, "nao gerado:", r.stderr.strip().splitlines()[-1] if r.stderr.strip() else r.returncode, ")")
    return chave, cert, feitos


# ----------------------------------------------------------------- documento
def ns_root(modo):
    """Variante A declara xmlns:ds na raiz. Variante B NAO declara: a Signature
    traz xmlns default proprio. NAO ligar o mesmo namespace a duas formas
    (default e prefixo): o C14N do lxml/libxml2 emite xmlns="" errado nesse caso
    e o xmlsec1 recalcula outros bytes."""
    ds = ('xmlns:ds="%s" ' % DS) if modo == "A" else ""
    return ('xmlns:p="http://www.giss.com.br/enviar-lote-rps-envio-v2_04.xsd" '
            'xmlns:p1="http://www.giss.com.br/tipos-v2_04.xsd" '
            + ds + 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')


def rps_xml(n, serie, valor, disc):
    # Dados 100% ficticios. Estrutura conforme tipos-v2_04.xsd.
    return (
        '<p1:Rps>'
        '<p1:InfDeclaracaoPrestacaoServico Id="rps%d">'
        '<p1:Rps><p1:IdentificacaoRps><p1:Numero>%d</p1:Numero><p1:Serie>%s</p1:Serie><p1:Tipo>1</p1:Tipo></p1:IdentificacaoRps>'
        '<p1:DataEmissao>2026-09-28</p1:DataEmissao><p1:Status>1</p1:Status></p1:Rps>'
        '<p1:Competencia>2026-09-28</p1:Competencia>'
        '<p1:Servico><p1:Valores><p1:ValorServicos>%s</p1:ValorServicos></p1:Valores>'
        '<p1:IssRetido>2</p1:IssRetido><p1:ItemListaServico>01.05</p1:ItemListaServico>'
        '<p1:Discriminacao>%s</p1:Discriminacao>'
        '<p1:CodigoMunicipio>3510401</p1:CodigoMunicipio><p1:ExigibilidadeISS>1</p1:ExigibilidadeISS></p1:Servico>'
        '<p1:Prestador><p1:CpfCnpj><p1:Cnpj>11222333000181</p1:Cnpj></p1:CpfCnpj><p1:InscricaoMunicipal>12345</p1:InscricaoMunicipal></p1:Prestador>'
        '<p1:TomadorServico><p1:IdentificacaoTomador><p1:CpfCnpj><p1:Cnpj>44555666000100</p1:Cnpj></p1:CpfCnpj></p1:IdentificacaoTomador>'
        '<p1:RazaoSocial>TOMADOR TESTE LTDA</p1:RazaoSocial></p1:TomadorServico>'
        '<p1:OptanteSimplesNacional>1</p1:OptanteSimplesNacional><p1:IncentivoFiscal>2</p1:IncentivoFiscal>'
        '</p1:InfDeclaracaoPrestacaoServico>'
        '@@SIG:rps%d@@'
        '</p1:Rps>'
    ) % (n, n, serie, valor, disc, n)


def sig_xml(modo, refid):
    """modo A: prefixo ds: (namespace declarado na raiz).
    modo B: xmlns default declarado na propria Signature (muito comum em
    implementacoes ABRASF; muda o C14N do SignedInfo)."""
    corpo = (
        '<SignedInfo>'
        '<CanonicalizationMethod Algorithm="%s"/>'
        '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        '<Reference URI="#%s"><Transforms>'
        '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        '<Transform Algorithm="%s"/>'
        '</Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
        '<DigestValue>@@D:%s@@</DigestValue></Reference></SignedInfo>'
        '<SignatureValue>@@S:%s@@</SignatureValue>'
        '<KeyInfo><X509Data><X509Certificate>@@CERT@@</X509Certificate></X509Data></KeyInfo>'
    ) % (C14N, refid, C14N, refid, refid)
    if modo == "A":
        import re
        corpo = re.sub(r"<(/?)([A-Za-z])", r"<\1ds:\2", corpo)
        return "<ds:Signature>" + corpo + "</ds:Signature>"
    return '<Signature xmlns="%s">' % DS + corpo + "</Signature>"


def montar_texto(modo):
    d1 = "ASSINATURA GENERICA &amp; CIA &lt;TESTE&gt;\\s\\n2\u00aa linha: a\u00e7\u00e3o \u20ac"
    d2 = "MENSALIDADE TESTE"
    t = ('<?xml version="1.0" encoding="UTF-8"?>'
         '<p:EnviarLoteRpsEnvio %s>'
         '<p:LoteRps Id="lote1" versao="2.04">'
         '<p1:NumeroLote>1</p1:NumeroLote>'
         '<p1:Prestador><p1:CpfCnpj><p1:Cnpj>11222333000181</p1:Cnpj></p1:CpfCnpj><p1:InscricaoMunicipal>12345</p1:InscricaoMunicipal></p1:Prestador>'
         '<p1:QuantidadeRps>2</p1:QuantidadeRps>'
         '<p1:ListaRps>%s%s</p1:ListaRps>'
         '</p:LoteRps>'
         '@@SIG:lote1@@'
         '</p:EnviarLoteRpsEnvio>') % (ns_root(modo), rps_xml(1, "A", "1.00", d1), rps_xml(2, "A", "2.50", d2))
    for rid in ("rps1", "rps2", "lote1"):
        t = t.replace("@@SIG:%s@@" % rid, sig_xml(modo, rid))
    return t


def parse(t):
    return etree.fromstring(t.encode("utf-8"))


def c14n_subarvore_direto(el):
    """C14N direto da sub-arvore pelo lxml. NAO USAR como referencia: o libxml2
    emite xmlns="" espurio quando o xmlns padrao vem de um ancestral que fica
    fora do trecho canonicalizado (comprovado contra o xmlsec1)."""
    return etree.tostring(el, method="c14n", exclusive=False, with_comments=False, with_tail=False)


def c14n(el):
    """C14N inclusivo 1.0 sem comentarios de `el` NO CONTEXTO do documento.
    Monta um elemento raiz novo com o nsmap COMPLETO em escopo (inclusive os
    xmlns nao usados, que o C14N inclusivo exige) e canonicaliza como documento,
    o que evita o defeito de sub-arvore do libxml2."""
    import copy
    novo = etree.Element(el.tag, attrib=dict(el.attrib), nsmap=el.nsmap)
    novo.text = el.text
    for filho in el:
        c = copy.deepcopy(filho)
        c.tail = filho.tail
        novo.append(c)
    return etree.tostring(novo, method="c14n", exclusive=False,
                          with_comments=False, with_tail=False)


def por_id(raiz, i):
    r = raiz.xpath('//*[@Id="%s"]' % i)
    assert len(r) == 1, "Id %s nao unico (%d)" % (i, len(r))
    return r[0]


def sig_da_ref(raiz, i):
    r = raiz.xpath('//*[local-name()="Signature"][.//*[local-name()="Reference"][@URI="#%s"]]' % i)
    assert len(r) == 1
    return r[0]


def assinar(modo, chave, cert):
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    t = montar_texto(modo).replace("@@CERT@@", cert_b64)
    passos = []
    # ordem OBRIGATORIA: cada RPS primeiro, lote por ultimo (o lote cobre as
    # assinaturas dos RPS, pois elas estao DENTRO de LoteRps).
    for rid in ("rps1", "rps2", "lote1"):
        raiz = parse(t)
        alvo = por_id(raiz, rid)
        assinatura = sig_da_ref(raiz, rid)
        # transform enveloped-signature: remove SO a Signature que contem esta
        # Reference, se ela for descendente do alvo. Aqui ela e irma/externa,
        # entao nada e removido — mas as Signature DOS RPS dentro de LoteRps FICAM.
        eh_desc = assinatura in alvo.iter()
        assert not eh_desc, "Signature nao deveria estar dentro do alvo"
        alvo_c14n = c14n(alvo)
        digest = base64.b64encode(hashlib.sha1(alvo_c14n).digest()).decode()
        t = t.replace("@@D:%s@@" % rid, digest)
        raiz = parse(t)
        si = raiz.xpath('//*[local-name()="Signature"][.//*[local-name()="Reference"][@URI="#%s"]]/*[local-name()="SignedInfo"]' % rid)[0]
        si_c14n = c14n(si)
        sv = chave.sign(si_c14n, padding.PKCS1v15(), hashes.SHA1())
        sv_b64 = base64.b64encode(sv).decode()
        t = t.replace("@@S:%s@@" % rid, sv_b64)
        tag = "-" + modo.lower()
        gravar("xml/passos/%s%s.alvo.c14n" % (rid, tag), alvo_c14n)
        gravar("xml/passos/%s%s.signedinfo.c14n" % (rid, tag), si_c14n)
        passos.append({"id": rid, "digest_sha1_b64": digest, "signature_value_b64": sv_b64,
                       "alvo_c14n": "xml/passos/%s%s.alvo.c14n" % (rid, tag),
                       "signedinfo_c14n": "xml/passos/%s%s.signedinfo.c14n" % (rid, tag)})
    assert "@@" not in t
    return t, passos


# ----------------------------------------------------------------- verificacao
def verificar(texto, cert):
    """Verificador independente do assinador acima (outro caminho de codigo):
    devolve {id_referenciado: True/False}."""
    raiz = parse(texto)
    pub = cert.public_key()
    res = {}
    for s in raiz.xpath('//*[local-name()="Signature"]'):
        ref = s.xpath('.//*[local-name()="Reference"]')[0]
        rid = ref.get("URI")[1:]
        try:
            alvo = por_id(raiz, rid)
            copia = etree.fromstring(etree.tostring(raiz))
            # enveloped-signature: remover a propria Signature se dentro do alvo
            a2 = por_id(copia, rid)
            for outra in a2.xpath('.//*[local-name()="Signature"]'):
                if [x for x in outra.xpath('.//*[local-name()="Reference"]') if x.get("URI") == "#" + rid]:
                    outra.getparent().remove(outra)
            dig = base64.b64encode(hashlib.sha1(c14n(a2)).digest()).decode()
            dig_ok = dig == ref.xpath('string(*[local-name()="DigestValue"])').strip()
            si = s.xpath('*[local-name()="SignedInfo"]')[0]
            sv = base64.b64decode(s.xpath('string(*[local-name()="SignatureValue"])'))
            try:
                pub.verify(sv, c14n(si), padding.PKCS1v15(), hashes.SHA1())
                sig_ok = True
            except Exception:
                sig_ok = False
            res[rid] = dig_ok and sig_ok
        except Exception:
            res[rid] = False
    return res


def xmlsec1(caminho, cert_pem):
    """Arbitro: xmlsec1 (referencia do mercado). Devolve lista de bool, uma por
    <Signature> em ordem de documento (rps1, rps2, lote1)."""
    import shutil
    if not shutil.which("xmlsec1"):
        return None
    res = []
    for n in (1, 2, 3):
        r = subprocess.run(["xmlsec1", "--verify", "--insecure", "--pubkey-cert-pem", cert_pem,
                            "--id-attr:Id", "LoteRps", "--id-attr:Id", "InfDeclaracaoPrestacaoServico",
                            "--node-xpath", '(//*[local-name()="Signature"])[%d]' % n, caminho],
                           capture_output=True, text=True)
        res.append(r.returncode == 0 and (r.stderr + r.stdout).lstrip().startswith("OK"))
    return res


# ----------------------------------------------------------------- casos c14n
CASOS = [
    ("01-heranca-e-declaracao-nao-usada",
     '<a:Raiz xmlns:a="urn:a" xmlns:b="urn:b" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:def"><b:Filho Id="alvo"><a:Neto/></b:Filho></a:Raiz>'),
    ("02-atributos-ordenados",
     '<r xmlns:q="urn:q" xmlns:z="urn:z"><e z:b="1" q:c="2" a="3" versao="2.04" Id="alvo"/></r>'),
    ("03-escape-texto",
     '<r><e Id="alvo">A &amp; B &lt; C &gt; D "q" \'a\' &#13; fim</e></r>'),
    ("04-escape-atributo",
     '<r><e Id="alvo" v="a&amp;b&lt;c&quot;d&#9;e&#10;f&#13;g&gt;h"/></r>'),
    ("05-vazio-expande",
     '<r><e Id="alvo"><v/><w></w></e></r>'),
    ("06-utf8-sem-entidade",
     '<r><e Id="alvo">GENERICA a\u00e7\u00e3o \u20ac</e></r>'),
    ("07-ns-redundante-removido",
     '<r xmlns:a="urn:a"><e Id="alvo" xmlns:a="urn:a"><a:f xmlns:a="urn:a"/></e></r>'),
    ("08-default-sobreposto",
     '<r xmlns="urn:one" xmlns:p="urn:p"><e Id="alvo" xmlns="urn:two"><f/></e></r>'),
    ("09-cdata-e-charref",
     '<r><e Id="alvo"><![CDATA[a<b&c]]>&#65;&#x42;</e></r>'),
    ("10-espacos-preservados",
     '<r><e Id="alvo">  x  <f/>  </e></r>'),
]


def gerar_casos_c14n():
    manifesto = []
    for nome, xml in CASOS:
        raiz = etree.fromstring(xml.encode("utf-8"))
        alvo = por_id(raiz, "alvo")
        esperado = c14n(alvo)
        gravar("c14n/%s.entrada.xml" % nome, xml)
        gravar("c14n/%s.esperado.c14n" % nome, esperado)
        manifesto.append({"nome": nome, "entrada": "c14n/%s.entrada.xml" % nome,
                          "alvo_id": "alvo", "esperado": "c14n/%s.esperado.c14n" % nome})
    gravar("c14n/manifesto.json", json.dumps(manifesto, indent=2, ensure_ascii=False))


# ----------------------------------------------------------------- principal
def main():
    chave, cert, pfx = gerar_certificados()
    print("PFX gerados:", pfx)
    gerar_casos_c14n()

    golden = {"senha_pfx": SENHA_PFX, "pfx": pfx, "variantes": {}, "negativos": []}
    finais = {}
    for modo in ("A", "B"):
        texto, passos = assinar(modo, chave, cert)
        finais[modo] = texto
        gravar("xml/lote-assinado-%s.xml" % modo.lower(), texto)
        # o mesmo documento SEM as assinaturas (entrada do assinador)
        gravar("xml/lote-sem-assinatura-%s.xml" % modo.lower(), sem_assinaturas(texto))
        v = verificar(texto, cert)
        assert all(v.values()) and len(v) == 3, ("verificacao da referencia falhou", modo, v)
        golden["variantes"][modo] = {"assinado": "xml/lote-assinado-%s.xml" % modo.lower(),
                                     "sem_assinatura": "xml/lote-sem-assinatura-%s.xml" % modo.lower(),
                                     "passos": passos}
        print("variante", modo, "verificada:", v)
        x = xmlsec1(esc("xml/lote-assinado-%s.xml" % modo.lower()), esc("certs/teste.crt.pem"))
        print("  xmlsec1 (arbitro):", x)
        assert x is None or x == [True, True, True], ("xmlsec1 DISCORDA da referencia", modo, x)

    # negativos (modo A)
    base = finais["A"]
    neg = {
        "n1-texto-do-rps1-alterado": (base.replace("MENSALIDADE TESTE", "MENSALIDADE ALTERADA").replace("ASSINATURA GENERICA", "ASSINATURA ALTERADA"), {"rps1": False, "rps2": False, "lote1": False}),
        "n2-numero-do-lote-alterado": (base.replace("<p1:NumeroLote>1<", "<p1:NumeroLote>9<"), {"rps1": True, "rps2": True, "lote1": False}),
        "n3-digest-do-rps1-trocado": (None, {"rps1": False, "rps2": True, "lote1": False}),
    }
    d1 = golden["variantes"]["A"]["passos"][0]["digest_sha1_b64"]
    neg["n3-digest-do-rps1-trocado"] = (base.replace(d1, base64.b64encode(hashlib.sha1(b"x").digest()).decode(), 1), neg["n3-digest-do-rps1-trocado"][1])
    for nome, (txt, esperado) in neg.items():
        assert txt != base, nome
        r = verificar(txt, cert)
        # confere que o verificador de referencia enxerga o que declaramos
        assert r == esperado, (nome, r, esperado)
        gravar("negativos/%s.xml" % nome, txt)
        x = xmlsec1(esc("negativos/%s.xml" % nome), esc("certs/teste.crt.pem"))
        esp = [esperado["rps1"], esperado["rps2"], esperado["lote1"]]
        print("  xmlsec1", nome, x, "esperado", esp)
        assert x is None or x == esp, ("xmlsec1 discorda no negativo", nome, x, esp)
        golden["negativos"].append({"arquivo": "negativos/%s.xml" % nome, "referencias_validas": esperado})
    print("negativos conferidos")

    gravar("golden.json", json.dumps(golden, indent=2, ensure_ascii=False))
    # copia do proprio gerador
    with open(__file__, "rb") as f:
        gravar("gerar_vetores.py", f.read())


def sem_assinaturas(t):
    import re
    t = re.sub(r"<ds:Signature>.*?</ds:Signature>", "", t, flags=re.S)
    t = re.sub(r'<Signature xmlns="[^"]+">.*?</Signature>', "", t, flags=re.S)
    return t


if __name__ == "__main__":
    main()
