javac -cp ".\pmd-core-7.17.0.jar;.\pmd-apex-7.17.0.jar" -d .\bin .\src\main\java\rules\InsecureDeserializationRule.java





jar cf InsecureDeserializationRule.jar -C bin .  