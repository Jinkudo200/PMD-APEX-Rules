// ExampleBatch.cls
global class ExampleBatch implements Database.Batchable<sObject> {
    global Database.QueryLocator start(Database.BatchableContext BC) {
        return Database.getQueryLocator('SELECT Id FROM Account');
    }

    global void execute(Database.BatchableContext BC, List<sObject> scope) {}

    global void finish(Database.BatchableContext BC) {}
}
