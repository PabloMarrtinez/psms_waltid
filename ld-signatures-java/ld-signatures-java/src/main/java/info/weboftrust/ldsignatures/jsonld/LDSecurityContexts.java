package info.weboftrust.ldsignatures.jsonld;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import foundation.identity.jsonld.ConfigurableDocumentLoader;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class LDSecurityContexts {

    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V1 = URI.create("https://w3id.org/security/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V2 = URI.create("https://w3id.org/security/v2");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V3 = URI.create("https://w3id.org/security/v3");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1 = URI.create("https://w3id.org/security/bbs/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SUITES_SECP256K1_2019_V1 = URI.create("https://w3id.org/security/suites/secp256k1-2019/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SUITES_ED25519_2018_V1 = URI.create("https://w3id.org/security/suites/ed25519-2018/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SUITES_ED25519_2020_V1 = URI.create("https://w3id.org/security/suites/ed25519-2020/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SUITES_X25519_2019_V1 = URI.create("https://w3id.org/security/suites/x25519-2019/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SUITES_JWS_2020_V1 = URI.create("https://w3id.org/security/suites/jws-2020/v1");


    //  UMU
    public static final URI JSONLD_CONTXT_WEID_SUITES_PSMS_BLS = URI.create("https://ssiproject.inf.um.es/security/psms/v1");
    public static final URI JSONLD_CONTXT_CREDENTIALS_2018 = URI.create("https://www.w3.org/2018/credentials/v1");
    public static final URI JSONLD_CONTXT_CITIZENSHIP_V1 = URI.create("https://w3id.org/citizenship/v1");

    public static final URI JSONLD_CONTXT_CREDENTIALS_EXAMPLES_V2 = URI.create("https://www.w3.org/ns/credentials/examples/v2");

    public static final URI JSONLD_CONTXT_CREDENTIALS_EXAMPLES_V1 = URI.create("https://www.w3.org/2018/credentials/examples/v1");
    public static final URI JSONLD_CONTXT_CREDENTIALS_V2 = URI.create("https://www.w3.org/ns/credentials/v2");

    public static final URI JSONLD_CONTXT_ODRL = URI.create("https://www.w3.org/ns/odrl.jsonld");

    public static final Map<URI, JsonDocument> CONTEXTS;
    public static final DocumentLoader DOCUMENT_LOADER;

    static {

        try {

            CONTEXTS = new HashMap<>();

            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("security-v1.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V2,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("security-v2.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V3,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("security-v3-unstable.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("security-bbs-v1.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SUITES_SECP256K1_2019_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("suites-secp256k1-2019.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SUITES_ED25519_2018_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("suites-ed25519-2018.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SUITES_ED25519_2020_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("suites-ed25519-2020.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SUITES_X25519_2019_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("suites-x25519-2019.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SUITES_JWS_2020_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("suites-jws-2020.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_WEID_SUITES_PSMS_BLS,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("context_psms_umu.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_CREDENTIALS_2018,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("credentials_v1_2018_umu.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_CITIZENSHIP_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("citizenship_v1_umu.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_CREDENTIALS_EXAMPLES_V2,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("w3_ns_credential_examples_v2.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_CREDENTIALS_V2,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("w3_ns_credential_v2.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_CREDENTIALS_EXAMPLES_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("credentials_v1_2018_umu_examples.jsonld"))));
            CONTEXTS.put(JSONLD_CONTXT_ODRL,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(LDSecurityContexts.class.getResourceAsStream("odrl.jsonld"))));
            for (Map.Entry<URI, JsonDocument> context : CONTEXTS.entrySet()) {
                context.getValue().setDocumentUrl(context.getKey());
            }
        } catch (JsonLdError ex) {

            throw new ExceptionInInitializerError(ex);
        }

        DOCUMENT_LOADER = new ConfigurableDocumentLoader(CONTEXTS);
    }
}
