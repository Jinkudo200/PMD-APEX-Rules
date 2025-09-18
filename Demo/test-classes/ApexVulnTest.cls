// ApexVulnTest.cls
public class ApexVulnTest {
    private String apiKey = 'SECRET_API_KEY_12345';

    public void insecureDeserialization(String jsonInput) {
        Object obj = JSON.deserialize(jsonInput, Object.class);
        System.debug(obj);
    }

    public void soqlInjection(String userInput) {
        String query = 'SELECT Id, Name FROM Account WHERE Name = \'' + userInput + '\'';
        List<Account> accounts = Database.query(query);
    }

    public void commandInjection(String userInput) {
        String cronExp = '0 0 12 * * ?';
        String jobName = 'Batch_' + userInput;
        System.schedule(jobName, cronExp, new ExampleBatch());
    }
}
