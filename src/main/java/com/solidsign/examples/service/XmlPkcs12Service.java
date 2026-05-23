package com.solidsign.examples.service;

import com.solidsign.examples.response.SignResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.util.List;
import java.util.zip.*;

/**
 * [EN]    XAdES (XML) signing service using a PKCS#12 certificate pre-imported into the cache.
 *
 *         Usage flow:
 *          1. Import the certificate ONCE:
 *               POST /solidsign/dsig/certificates/pkcs12/import
 *               Body (multipart): pfxCertificate=<file.pfx>, pfxPassword=<base64-password>
 *             Response: { "id": "<uuid>", "alias": "...", "expirationDate": "..." }
 *          2. Set the returned UUID in solidsign.cert.id (application.properties).
 *          3. On every signing request, only the UUID is sent as "pfxCode".
 *
 * [PT-BR] Serviço de assinatura XAdES (XML) utilizando certificado PKCS#12 pré-importado na cache.
 *
 *         Fluxo de uso:
 *          1. Importe o certificado UMA VEZ:
 *               POST /solidsign/dsig/certificates/pkcs12/import
 *               Body (multipart): pfxCertificate=<arquivo.pfx>, pfxPassword=<senha-base64>
 *             Resposta: { "id": "<uuid>", "alias": "...", "expirationDate": "..." }
 *          2. Configure o UUID retornado em solidsign.cert.id (application.properties).
 *          3. A cada requisição de assinatura, apenas o UUID é enviado como "pfxCode".
 *
 * [ES]    Servicio de firma XAdES (XML) utilizando un certificado PKCS#12 pre-importado en la caché.
 *
 *         Flujo de uso:
 *          1. Importe el certificado UNA VEZ:
 *               POST /solidsign/dsig/certificates/pkcs12/import
 *               Body (multipart): pfxCertificate=<archivo.pfx>, pfxPassword=<contraseña-base64>
 *             Respuesta: { "id": "<uuid>", "alias": "...", "expirationDate": "..." }
 *          2. Configure el UUID devuelto en solidsign.cert.id (application.properties).
 *          3. En cada solicitud de firma, solo el UUID se envía como "pfxCode".
 */
@Service
public class XmlPkcs12Service {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlPkcs12Service.class);
    private final RestTemplate restTemplate = new RestTemplate();

    // [EN]    Base URL of the SolidSign API
    // [PT-BR] URL base da API SolidSign
    // [ES]    URL base de la API SolidSign
    @Value("${solidsign.api.base-url}")
    private String baseUrl;

    // [EN]    Authorization header value (Bearer token)
    // [PT-BR] Valor do header Authorization (token Bearer)
    // [ES]    Valor del header Authorization (token Bearer)
    @Value("${solidsign.api.authorization}")
    private String authorization;

    // [EN]    Signature profile (e.g. ADRB, ADRT, ADRC, ADRA)
    // [PT-BR] Perfil de assinatura (ex: ADRB, ADRT, ADRC, ADRA)
    // [ES]    Perfil de firma (p.ej. ADRB, ADRT, ADRC, ADRA)
    @Value("${solidsign.sig.profile}")
    private String profile;

    // [EN]    Hash algorithm (SHA256, SHA384, SHA512)
    // [PT-BR] Algoritmo de hash (SHA256, SHA384, SHA512)
    // [ES]    Algoritmo de hash (SHA256, SHA384, SHA512)
    @Value("${solidsign.sig.hashAlgorithm}")
    private String hashAlgorithm;

    // [EN]    Policy version (e.g. 1_3)
    // [PT-BR] Versão da política (ex: 1_3)
    // [ES]    Versión de la política (p.ej. 1_3)
    @Value("${solidsign.sig.policyVersion}")
    private String policyVersion;

    // [EN]    Signature packaging (ENVELOPED, ENVELOPING, DETACHED)
    // [PT-BR] Empacotamento da assinatura (ENVELOPED, ENVELOPING, DETACHED)
    // [ES]    Empaquetado de la firma (ENVELOPED, ENVELOPING, DETACHED)
    @Value("${solidsign.sig.signaturePackaging}")
    private String signaturePackaging;

    // [EN]    Local name of the XML node to sign
    // [PT-BR] Nome local do nó XML a assinar
    // [ES]    Nombre local del nodo XML a firmar
    @Value("${solidsign.sig.signatureNodeName}")
    private String signatureNodeName;

    // [EN]    Namespace URI of the XML node to sign
    // [PT-BR] URI de namespace do nó XML a assinar
    // [ES]    URI de namespace del nodo XML a firmar
    @Value("${solidsign.sig.signatureNodeNamespace}")
    private String signatureNodeNamespace;

    // [EN]    XML canonicalization algorithm URI
    // [PT-BR] URI do algoritmo de canonicalização XML
    // [ES]    URI del algoritmo de canonicalización XML
    @Value("${solidsign.sig.canonicalizationMethod}")
    private String canonicalizationMethod;

    /**
     * [EN]    Signs the given XML files via XAdES using the UUID of the pre-imported certificate.
     * [PT-BR] Assina os XMLs informados via XAdES usando o UUID do certificado pré-importado.
     * [ES]    Firma los archivos XML indicados vía XAdES usando el UUID del certificado pre-importado.
     *
     * @param xmlFiles
     *   [EN]    XML files to sign
     *   [PT-BR] arquivos XML a assinar
     *   [ES]    archivos XML a firmar
     * @param certId
     *   [EN]    UUID of the imported certificate (value of solidsign.cert.id)
     *   [PT-BR] UUID do certificado importado (valor de solidsign.cert.id)
     *   [ES]    UUID del certificado importado (valor de solidsign.cert.id)
     * @param outputDir
     *   [EN]    destination folder for the ZIP of signed files
     *   [PT-BR] pasta de destino do ZIP com os arquivos assinados
     *   [ES]    carpeta de destino del ZIP con los archivos firmados
     * @return
     *   [EN]    path of the generated ZIP, or null on error
     *   [PT-BR] caminho do ZIP gerado, ou null em caso de erro
     *   [ES]    ruta del ZIP generado, o null en caso de error
     */
    public String signPkcs12(List<File> xmlFiles, String certId, String outputDir) throws IOException {
        LOGGER.info("Starting XAdES PKCS12 signing for {} XML(s) using certId={}.", xmlFiles.size(), certId);

        // [EN]    Build the full endpoint URL from the base URL
        // [PT-BR] Constrói a URL completa do endpoint a partir da URL base
        // [ES]    Construye la URL completa del endpoint a partir de la URL base
        String signUrl = baseUrl + "/solidsign/dsig/xml/sign-pkcs12";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("Authorization", authorization);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();

        // [EN]    Attach each XML indexed as document[0], document[1], ...
        // [PT-BR] Anexa cada XML indexado como document[0], document[1], ...
        // [ES]    Adjunta cada XML indexado como document[0], document[1], ...
        for (int i = 0; i < xmlFiles.size(); i++) {
            body.add("document[" + i + "]", new FileSystemResource(xmlFiles.get(i)));
        }

        // [EN]    Pre-imported certificate UUID — sent as "pfxCode", not the raw PFX file
        // [PT-BR] UUID do certificado pré-importado — enviado como "pfxCode", não o arquivo PFX bruto
        // [ES]    UUID del certificado pre-importado — enviado como "pfxCode", no el archivo PFX bruto
        body.add("pfxCode", certId);

        // [EN]    Signature parameters
        // [PT-BR] Parâmetros de assinatura
        // [ES]    Parámetros de firma
        body.add("profile",                profile);
        body.add("hashAlgorithm",          hashAlgorithm);
        body.add("policyVersion",          policyVersion);
        body.add("signaturePackaging",     signaturePackaging);
        body.add("signatureNodeName",      signatureNodeName);
        body.add("signatureNodeNamespace", signatureNodeNamespace);
        body.add("canonicalizationMethod", canonicalizationMethod);

        // [EN]    XPath and namespace prefix options — set to false for standard usage
        // [PT-BR] Opções de XPath e prefixo de namespace — defina como false para uso padrão
        // [ES]    Opciones de XPath y prefijo de namespace — configurar en false para uso estándar
        body.add("isRemoveXPathExclusionFilter",        "false");
        body.add("isRemoveNamespacePrefixFromNodeNames", "false");
        body.add("isSignKeyInfo",                        "false");

        try {
            ResponseEntity<SignResponse> resp = restTemplate.postForEntity(
                    signUrl, new HttpEntity<>(body, headers), SignResponse.class);
            if (resp.getStatusCode() == HttpStatus.OK && resp.getBody() != null) {
                byte[] zip = downloadAndZip(resp.getBody(), xmlFiles);
                new File(outputDir).mkdirs();
                String out = outputDir + "/signed_xml_pkcs12_" + System.currentTimeMillis() + ".zip";
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    fos.write(zip);
                }
                LOGGER.info("XAdES PKCS12 signing complete. Output: {}", out);
                return out;
            }
        } catch (HttpStatusCodeException e) {
            LOGGER.error("SolidSign API error {}: {}", e.getStatusCode(), e.getResponseBodyAsString());
        } catch (Exception e) {
            LOGGER.error("Unexpected error during XAdES PKCS12 signing: {}", e.getMessage(), e);
        }
        return null;
    }

    /**
     * [EN]    Downloads each signed document from the SolidSign response links and packages them into a ZIP.
     * [PT-BR] Baixa cada documento assinado dos links da resposta SolidSign e os empacota em um ZIP.
     * [ES]    Descarga cada documento firmado de los enlaces de respuesta SolidSign y los empaqueta en un ZIP.
     */
    private byte[] downloadAndZip(SignResponse resp, List<File> originals) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", authorization);
            HttpEntity<Void> entity = new HttpEntity<>(headers);
            for (int i = 0; i < resp.documents.size(); i++) {
                String downloadUrl = resp.documents.get(i).links.stream()
                        .filter(l -> "self".equals(l.rel))
                        .findFirst()
                        .map(l -> l.href)
                        .orElse(null);
                if (downloadUrl == null) continue;
                ResponseEntity<byte[]> r = restTemplate.exchange(
                        downloadUrl, HttpMethod.GET, entity, byte[].class);
                if (r.getStatusCode() == HttpStatus.OK) {
                    zos.putNextEntry(new ZipEntry("signed_" + originals.get(i).getName()));
                    zos.write(r.getBody());
                    zos.closeEntry();
                }
            }
        }
        return baos.toByteArray();
    }
}
