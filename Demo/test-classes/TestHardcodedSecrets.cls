public class TestHardcodedSecrets {

    // =========================
    // Hardcoded secrets (Rule: HardcodedSecretsRule)
    // =========================
    private String apiKey = '12345-SECRET-KEY';
    private String password = 'MyP@ssw0rd!';
    private String token = 'token_ABC123';

    public void useSecrets() {
        System.debug('API Key: ' + apiKey);
        System.debug('Password: ' + password);
        System.debug('Token: ' + token);
    }

    // =========================
    // Deprecated methods (Rule: DeprecatedMethodsRule)
    // =========================
    public void useDeprecatedMethods() {
        // Example using SHA1/MD5
        Blob sha1Digest = Crypto.generateDigest('SHA1', Blob.valueOf('test'));
        Blob md5Digest = Crypto.generateDigest('MD5', Blob.valueOf('test'));
        System.debug(sha1Digest);
        System.debug(md5Digest);
    }

    // =========================
    // Insecure deserialization (Rule: InsecureDeserializationRule)
    // =========================
    public void insecureDeserialization() {
        String json = '{"name":"Ayman"}';
        Object obj = JSON.deserialize(json, Object.class);
        System.debug(obj);
    }

    // =========================
    // Insecure XML parsing (Rule: InsecureXMLParserRule)
    // =========================
    public void insecureXMLParsing() {
        String xmlString = '<root><child>value</child></root>';
        Dom.Document doc1 = new Dom.Document();
        doc1.load(xmlString);    // insecure
        Dom.Document doc2 = new Dom.Document();
        doc2.parse(xmlString);   // insecure
    }
}
