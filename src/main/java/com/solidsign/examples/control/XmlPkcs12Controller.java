package com.solidsign.examples.control;

import com.solidsign.examples.service.XmlPkcs12Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.multipart.MultipartFile;

/**
 * [EN]    REST controller that signs XML (XAdES) documents using a pre-imported PKCS#12 certificate.
 *         The certificate must be imported once via POST /solidsign/dsig/certificates/pkcs12/import.
 *         After import, only the returned UUID (pfxCode) is sent on each signing request.
 *
 * [PT-BR] Controller REST que assina documentos XML (XAdES) usando um certificado PKCS#12 pré-importado.
 *         O certificado deve ser importado uma única vez via POST /solidsign/dsig/certificates/pkcs12/import.
 *         Após a importação, apenas o UUID retornado (pfxCode) é enviado em cada requisição de assinatura.
 *
 * [ES]    Controller REST que firma documentos XML (XAdES) usando un certificado PKCS#12 pre-importado.
 *         El certificado debe importarse una vez via POST /solidsign/dsig/certificates/pkcs12/import.
 *         Después de la importación, solo el UUID devuelto (pfxCode) se envía en cada solicitud de firma.
 */
@RestController
@RequestMapping("/api/xml")
public class XmlPkcs12Controller {

    private static final Logger LOGGER = LoggerFactory.getLogger(XmlPkcs12Controller.class);

    @Autowired
    private XmlPkcs12Service service;

    /**
     * [EN]    UUID of the PKCS#12 certificate previously imported via
     *         POST /solidsign/dsig/certificates/pkcs12/import.
     *         This ID is sent as "pfxCode" on every signing request,
     *         eliminating the need to upload the PFX file on each call.
     *
     * [PT-BR] UUID do certificado PKCS#12 previamente importado via
     *         POST /solidsign/dsig/certificates/pkcs12/import.
     *         Esse ID é enviado como "pfxCode" em cada requisição de assinatura,
     *         eliminando a necessidade de enviar o arquivo PFX a cada chamada.
     *
     * [ES]    UUID del certificado PKCS#12 previamente importado mediante
     *         POST /solidsign/dsig/certificates/pkcs12/import.
     *         Este ID se envía como "pfxCode" en cada solicitud de firma,
     *         eliminando la necesidad de subir el archivo PFX en cada llamada.
     */
    @Value("${solidsign.cert.id}")
    private String certId;

    // [EN]    Path to the folder containing XML files to sign
    // [PT-BR] Caminho para a pasta contendo os arquivos XML a assinar
    // [ES]    Ruta a la carpeta que contiene los archivos XML a firmar
    @Value("${solidsign.batch.input-path}")
    private String inputPath;

    // [EN]    Path to the folder where the signed ZIP will be written
    // [PT-BR] Caminho para a pasta onde o ZIP assinado será gravado
    // [ES]    Ruta a la carpeta donde se escribirá el ZIP firmado
    @Value("${solidsign.batch.output-path}")
    private String outputPath;

    /**
     * [EN]    Signs all XML files in the input folder using XAdES with the pre-imported PKCS#12 certificate.
     *         Returns the path of the output ZIP on success.
     *
     * [PT-BR] Assina todos os XMLs da pasta de entrada usando XAdES com o certificado PKCS#12 pré-importado.
     *         Retorna o caminho do ZIP de saída em caso de sucesso.
     *
     * [ES]    Firma todos los archivos XML de la carpeta de entrada con XAdES usando el certificado PKCS#12 pre-importado.
     *         Devuelve la ruta del ZIP de salida en caso de éxito.
     */
    @PostMapping("/sign-pkcs12")
    public ResponseEntity<String> signFolder() throws IOException {
        File folder = new File(inputPath);
        if (!folder.exists() || !folder.isDirectory()) {
            // [EN]    Configured input path is invalid or not a directory
            // [PT-BR] O caminho de entrada configurado é inválido ou não é um diretório
            // [ES]    La ruta de entrada configurada es inválida o no es un directorio
            return ResponseEntity.badRequest().body("Invalid input path: " + inputPath);
        }
        File[] files = folder.listFiles((d, n) -> n.toLowerCase().endsWith(".xml"));
        if (files == null || files.length == 0) {
            // [EN]    No XML files found in the input folder
            // [PT-BR] Nenhum arquivo XML encontrado na pasta de entrada
            // [ES]    No se encontraron archivos XML en la carpeta de entrada
            return ResponseEntity.ok("No XML files found in " + inputPath);
        }
        LOGGER.info("Found {} XML(s) for PKCS12 signing.", files.length);
        String result = service.signPkcs12(Arrays.asList(files), certId, outputPath);
        return result != null
                ? ResponseEntity.ok("Signed! ZIP at: " + result)
                : ResponseEntity.internalServerError().body("Failed. Check logs.");
    }

    /**
     * [EN]    Form signing endpoint for React front-end — XAdES PKCS#12. properties ignored.
     * [PT-BR] Endpoint de formulário para React — XAdES PKCS#12. properties ignorado.
     * [ES]    Endpoint de formulario para React — XAdES PKCS#12. properties ignorado.
     */
    @CrossOrigin
    @PostMapping("/sign/form")
    public ResponseEntity<byte[]> signForm(
            @RequestPart("document")                                                   MultipartFile[] documents,
            @RequestPart("authorization")                                              String authorization,
            @RequestPart("baseUrl")                                                    String baseUrl,
            @RequestPart("pfxCode")                                                    String pfxCode,
            @RequestPart(value = "profile",                         required = false)  String profile,
            @RequestPart(value = "hashAlgorithm",                   required = false)  String hashAlgorithm,
            @RequestPart(value = "signaturePackaging",              required = false)  String signaturePackaging,
            @RequestPart(value = "policyVersion",                   required = false)  String policyVersion,
            @RequestPart(value = "canonicalizationMethod",          required = false)  String canonicalizationMethod,
            @RequestPart(value = "signatureNodeName",               required = false)  String signatureNodeName,
            @RequestPart(value = "signatureNodeNamespace",          required = false)  String signatureNodeNamespace,
            @RequestPart(value = "isRemoveXPathExclusionFilter",    required = false)  String isRemoveXPathExclusionFilter,
            @RequestPart(value = "isRemoveNamespacePrefixFromNodeNames", required = false) String isRemoveNamespacePrefixFromNodeNames,
            @RequestPart(value = "isSignKeyInfo",                   required = false)  String isSignKeyInfo,
            @RequestPart(value = "signatureNodeId",                 required = false)  String signatureNodeId
    ) throws IOException {
        List<File> tmpFiles = new ArrayList<>();
        java.nio.file.Path tmpDir = java.nio.file.Files.createTempDirectory("solidsign-form-");
        try {
            for (MultipartFile mf : documents) {
                java.nio.file.Path p = tmpDir.resolve(
                        mf.getOriginalFilename() != null ? mf.getOriginalFilename() : "doc");
                mf.transferTo(p);
                tmpFiles.add(p.toFile());
            }
            byte[] zip = service.signPkcs12Form(authorization, baseUrl, pfxCode,
                    profile, hashAlgorithm, signaturePackaging, policyVersion,
                    canonicalizationMethod, signatureNodeName, signatureNodeNamespace,
                    isRemoveXPathExclusionFilter, isRemoveNamespacePrefixFromNodeNames,
                    isSignKeyInfo, signatureNodeId, tmpFiles);
            if (zip != null)
                return ResponseEntity.ok()
                        .contentType(org.springframework.http.MediaType.parseMediaType("application/zip"))
                        .header("Content-Disposition", "attachment; filename=\"signed.zip\"")
                        .body(zip);
            return ResponseEntity.internalServerError().build();
        } finally {
            tmpFiles.forEach(java.io.File::delete);
            tmpDir.toFile().delete();
        }
    }
}
