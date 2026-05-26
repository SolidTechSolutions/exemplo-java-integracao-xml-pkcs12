# 🇧🇷 SolidSign API - Exemplo de Assinatura XML PKCS12 (Batch Mode)

Este projeto demonstra a integração com a **SolidSign API** para realizar a assinatura digital XAdES de múltiplos arquivos XML em lote, utilizando um certificado PKCS#12 pré-importado. O arquivo resultante contém a assinatura digital incorporada ou destacada conforme o modo de empacotamento configurado.

## Estrutura do Projeto

* **Controller:** Atua como gatilho para escanear a pasta de entrada local e gerenciar o processo de assinatura XAdES.
* **Service:** Orquestra a chamada para a API SolidSign, trata erros 400/500 e salva o arquivo ZIP com os documentos assinados no armazenamento local.

## Configuração (application.properties)

| Atributo | Descrição | Exemplo / Valor |
| :--- | :--- | :--- |
| `solidsign.api.base-url` | URL base da SolidSign API (sem o caminho). | `https://solidsign.com.br` |
| `solidsign.api.authorization` | Token JWT de autorização (Bearer). | `Bearer eyJhbGciOiJIUzI1...` |
| `solidsign.cert.id` | UUID do certificado PKCS#12 pré-importado via `POST /solidsign/dsig/certificates/pkcs12/import`. | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `solidsign.batch.input-path` | Pasta local com os arquivos XML a serem assinados (modo lote). | `C:/Users/User/Desktop/input_files` |
| `solidsign.batch.output-path` | Pasta onde o ZIP com os arquivos assinados será salvo. | `C:/Users/User/Desktop/signed_results` |
| `solidsign.sig.hashAlgorithm` | Algoritmo de hash criptográfico (SHA256, SHA384, SHA512). | `SHA256` |
| `solidsign.sig.profile` | Perfil da assinatura XAdES (ICP-Brasil/ETSI). | `ADRB`, `ADRT`, `XADES_B`, `XADES_T`, `XADES_LT`, `XADES_LTA` |
| `solidsign.sig.signaturePackaging` | Modo de empacotamento da assinatura XAdES. | `ENVELOPED`, `ENVELOPING` ou `DETACHED` |
| `solidsign.sig.signatureNodeName` | Nome local do elemento XML onde a assinatura será inserida (XPath target). | `NFe` |
| `solidsign.sig.signatureNodeNamespace` | Namespace URI do elemento alvo da assinatura no XML. | `http://www.portalfiscal.inf.br/nfe` |
| `solidsign.sig.canonicalizationMethod` | Algoritmo de canonicalização XML (C14N). | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| `solidsign.sig.isRemoveXPathExclusionFilter` | Remove o filtro XPath de exclusão antes de assinar (true/false). | `false` |
| `solidsign.sig.isRemoveNamespacePrefixFromNodeNames` | Remove prefixos de namespace dos nomes dos nós antes de assinar (true/false). | `false` |
| `solidsign.sig.isSignKeyInfo` | Inclui o elemento KeyInfo no escopo da assinatura (true/false). | `false` |
| `solidsign.sig.signatureNodeId` *(opcional)* | ID do nó XML alvo quando há múltiplos elementos elegíveis para assinatura. | `NFe35...` |
| `solidsign.sig.policyVersion` *(opcional)* | OID da política de assinatura ICP-Brasil. | `2.16.76.1.7.1.1.2.4` |

## Stack
1. Java 17
2. SpringBoot 3.4.x+
3. Maven 3.x.x+
4. Logback (para logging dos erros)

## Como Executar

1. **Importar certificado:** Envie o arquivo `.pfx` e a senha (Base64) via `POST /solidsign/dsig/certificates/pkcs12/import` na SolidSign API e anote o `certId` retornado.
2. **Configurar:** Defina `solidsign.cert.id` com o UUID obtido e configure os demais parâmetros em `src/main/resources/application.properties`.
3. **Compilar:** `mvn clean install`
4. **Iniciar:** `mvn spring-boot:run`
5. **Testar:** Envie um POST para `http://localhost:8080/api/xml/sign-pkcs12`. O sistema processará automaticamente todos os arquivos XML encontrados na pasta de entrada.

## Tratamento de Erros
O sistema intercepta erros **400 Bad Request** e loga o JSON detalhado da SolidSign para facilitar o debug de certificados ou parâmetros inválidos.

---

# 🇬🇧 SolidSign API - XML PKCS12 Signature Example (Batch Mode)

This project demonstrates the integration with the **SolidSign API** to perform XAdES digital signatures on multiple XML files in batch mode, using a pre-imported PKCS#12 certificate. The resulting file contains the digital signature either embedded or detached depending on the configured packaging mode.

## Project Structure

* **Controller:** Acts as a trigger to scan the local input folder and manage the XAdES signing process.
* **Service:** Orchestrates the SolidSign API calls, handles 400/500 errors, and saves the ZIP file with signed documents to local storage.

## Configuration (application.properties)

| Attribute | Description | Example / Value |
| :--- | :--- | :--- |
| `solidsign.api.base-url` | Base URL of the SolidSign API (without path). | `https://solidsign.com.br` |
| `solidsign.api.authorization` | Authorization JWT Token (Bearer). | `Bearer eyJhbGciOiJIUzI1...` |
| `solidsign.cert.id` | UUID of the PKCS#12 certificate previously imported via `POST /solidsign/dsig/certificates/pkcs12/import`. | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `solidsign.batch.input-path` | Local folder containing the XML files to be signed (batch mode). | `C:/Users/User/Desktop/input_files` |
| `solidsign.batch.output-path` | Local folder where the signed ZIP file will be saved. | `C:/Users/User/Desktop/signed_results` |
| `solidsign.sig.hashAlgorithm` | Cryptographic hash algorithm (SHA256, SHA384, SHA512). | `SHA256` |
| `solidsign.sig.profile` | XAdES signature profile (ICP-Brasil/ETSI). | `ADRB`, `ADRT`, `XADES_B`, `XADES_T`, `XADES_LT`, `XADES_LTA` |
| `solidsign.sig.signaturePackaging` | XAdES signature packaging mode. | `ENVELOPED`, `ENVELOPING` or `DETACHED` |
| `solidsign.sig.signatureNodeName` | Local name of the XML element where the signature will be inserted (XPath target). | `NFe` |
| `solidsign.sig.signatureNodeNamespace` | Namespace URI of the target element in the XML. | `http://www.portalfiscal.inf.br/nfe` |
| `solidsign.sig.canonicalizationMethod` | XML canonicalization algorithm (C14N). | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| `solidsign.sig.isRemoveXPathExclusionFilter` | Removes the XPath exclusion filter before signing (true/false). | `false` |
| `solidsign.sig.isRemoveNamespacePrefixFromNodeNames` | Removes namespace prefixes from node names before signing (true/false). | `false` |
| `solidsign.sig.isSignKeyInfo` | Includes the KeyInfo element in the signature scope (true/false). | `false` |
| `solidsign.sig.signatureNodeId` *(optional)* | ID of the target XML node when there are multiple eligible elements for signing. | `NFe35...` |
| `solidsign.sig.policyVersion` *(optional)* | ICP-Brasil signature policy OID. | `2.16.76.1.7.1.1.2.4` |

## Stack
1. Java 17
2. SpringBoot 3.4.x+
3. Maven 3.x.x+
4. Logback (for error logging)

## How to Run

1. **Import certificate:** Upload the `.pfx` file and password (Base64) via `POST /solidsign/dsig/certificates/pkcs12/import` and note the returned `certId`.
2. **Configure:** Set `solidsign.cert.id` with the obtained UUID and configure the remaining parameters in `src/main/resources/application.properties`.
3. **Build:** `mvn clean install`
4. **Start:** `mvn spring-boot:run`
5. **Test:** Send a POST request to `http://localhost:8080/api/xml/sign-pkcs12`. The application will automatically process all XML files found in the input folder.

## Error Handling
The system intercepts **400 Bad Request** errors and logs the detailed JSON response from SolidSign to assist in debugging invalid certificates or parameters.

---

# 🇪🇸 SolidSign API - Ejemplo de Firma XML PKCS12 (Modo Batch)

Este proyecto demuestra la integración con la **SolidSign API** para realizar la firma digital XAdES de múltiples archivos XML en lote, usando un certificado PKCS#12 pre-importado. El archivo resultante contiene la firma digital incorporada o separada según el modo de empaquetado configurado.

## Estructura del Proyecto

* **Controller:** Actúa como disparador para escanear la carpeta local de entrada y gestionar el proceso de firma XAdES.
* **Service:** Orquestra las llamadas a la API SolidSign, gestiona errores 400/500 y guarda el archivo ZIP con los documentos firmados en el almacenamiento local.

## Configuración (application.properties)

| Atributo | Descripción | Ejemplo / Valor |
| :--- | :--- | :--- |
| `solidsign.api.base-url` | URL base de la SolidSign API (sin la ruta). | `https://solidsign.com.br` |
| `solidsign.api.authorization` | Token JWT de autorización (Bearer). | `Bearer eyJhbGciOiJIUzI1...` |
| `solidsign.cert.id` | UUID del certificado PKCS#12 pre-importado mediante `POST /solidsign/dsig/certificates/pkcs12/import`. | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `solidsign.batch.input-path` | Carpeta local con los archivos XML a firmar (modo lote). | `C:/Users/User/Desktop/input_files` |
| `solidsign.batch.output-path` | Carpeta donde se guardará el ZIP con los archivos firmados. | `C:/Users/User/Desktop/signed_results` |
| `solidsign.sig.hashAlgorithm` | Algoritmo de hash criptográfico (SHA256, SHA384, SHA512). | `SHA256` |
| `solidsign.sig.profile` | Perfil de firma XAdES (ICP-Brasil/ETSI). | `ADRB`, `ADRT`, `XADES_B`, `XADES_T`, `XADES_LT`, `XADES_LTA` |
| `solidsign.sig.signaturePackaging` | Modo de empaquetado de la firma XAdES. | `ENVELOPED`, `ENVELOPING` o `DETACHED` |
| `solidsign.sig.signatureNodeName` | Nombre local del elemento XML donde se insertará la firma (destino XPath). | `NFe` |
| `solidsign.sig.signatureNodeNamespace` | URI del namespace del elemento objetivo en el XML. | `http://www.portalfiscal.inf.br/nfe` |
| `solidsign.sig.canonicalizationMethod` | Algoritmo de canonicalización XML (C14N). | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| `solidsign.sig.isRemoveXPathExclusionFilter` | Elimina el filtro de exclusión XPath antes de firmar (true/false). | `false` |
| `solidsign.sig.isRemoveNamespacePrefixFromNodeNames` | Elimina los prefijos de namespace de los nombres de nodos antes de firmar (true/false). | `false` |
| `solidsign.sig.isSignKeyInfo` | Incluye el elemento KeyInfo en el alcance de la firma (true/false). | `false` |
| `solidsign.sig.signatureNodeId` *(opcional)* | ID del nodo XML objetivo cuando hay múltiples elementos elegibles para firma. | `NFe35...` |
| `solidsign.sig.policyVersion` *(opcional)* | OID de la política de firma ICP-Brasil. | `2.16.76.1.7.1.1.2.4` |

## Stack
1. Java 17
2. SpringBoot 3.4.x+
3. Maven 3.x.x+
4. Logback (para el registro de errores)

## Cómo Ejecutar

1. **Importar certificado:** Suba el archivo `.pfx` y la contraseña (Base64) mediante `POST /solidsign/dsig/certificates/pkcs12/import` y anote el `certId` devuelto.
2. **Configurar:** Defina `solidsign.cert.id` con el UUID obtenido y configure los demás parámetros en `src/main/resources/application.properties`.
3. **Compilar:** `mvn clean install`
4. **Iniciar:** `mvn spring-boot:run`
5. **Probar:** Envíe una solicitud POST a `http://localhost:8080/api/xml/sign-pkcs12`. La aplicación procesará automáticamente todos los archivos XML encontrados en la carpeta de entrada.

## Gestión de Errores
El sistema intercepta errores **400 Bad Request** y registra el JSON detallado de SolidSign para facilitar la depuración de certificados o parámetros inválidos.
