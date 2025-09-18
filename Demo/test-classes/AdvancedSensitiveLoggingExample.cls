public class AdvancedSensitiveLoggingExample {

    // Hardcoded secret fields
    private String apiKey = 'XYZ123APIKEYSECRET';
    private String adminPassword = 'AdminPass!2025';

    public void logAllSensitiveData(String dynamicToken, String userEmail, String userSSN) {
        // Direct hardcoded secret logging
        System.debug('API Key: ' + apiKey);          // triggers "looksLikeSensitive"
        System.debug('Admin Password: ' + adminPassword); // triggers "looksLikeSensitive"

        // Dynamic sensitive logging
        System.debug('Dynamic Token: ' + dynamicToken);   // triggers "looksLikeSensitive" if token looks like secret

        // Logging user PII
        System.debug('User Email: ' + userEmail);   // triggers "looksLikePII"
        System.debug('User SSN: ' + userSSN);       // triggers "looksLikePII"

        // Logging multiple sensitive variables concatenated
        String combinedInfo = 'Email=' + userEmail + '; Token=' + dynamicToken;
        System.debug('Combined Info: ' + combinedInfo);  // triggers both PII and sensitive detection

        // Logging inside loops
        String[] emails = new String[]{'john@example.com','alice@example.com'};
        for (String e : emails) {
            System.debug('Loop Email: ' + e);       // triggers PII
        }

        // Conditional logging
        if (dynamicToken != null && dynamicToken.startsWith('A')) {
            System.debug('Conditional Token Logging: ' + dynamicToken); // triggers sensitive
        }
    }
}
