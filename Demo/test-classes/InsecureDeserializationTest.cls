@RestResource(urlMapping='/UnsafeDeserialize/*')
global with sharing class InsecureDeserializationTest {

    // 1. Unsafe deserialization from REST request body
    @HttpPost
    global static void deserializeRestBody() {
        String body = RestContext.request.requestBody.toString();
        // Unsafe: comes directly from untrusted source
        Object obj = JSON.deserialize(body, Object.class);
        System.debug(obj);
    }

    // 2. Unsafe deserialization from page parameters
    public static void deserializePageParams() {
        String param = ApexPages.currentPage().getParameters().get('json');
        // Unsafe: untrusted input
        Map<String, Object> mapObj = (Map<String, Object>) JSON.deserialize(param, Map<String, Object>.class);
        System.debug(mapObj);
    }

    // 3. Unsafe deserialization with strict type
    public static void deserializeStrictExample() {
        String json = RestContext.request.requestBody.toString();
        // Unsafe: strict deserialization but still unvalidated
        MyWrapper mw = (MyWrapper) JSON.deserializeStrict(json, MyWrapper.class);
        System.debug(mw);
    }

    // 4. Nested unsafe deserialization
    public static void nestedDeserialize() {
        String json = RestContext.request.requestBody.toString();
        List<MyWrapper> wrappers = (List<MyWrapper>) JSON.deserialize(json, List<MyWrapper>.class);
        for (MyWrapper w : wrappers) {
            System.debug(w.name);
        }
    }

    // Wrapper class for testing
    public class MyWrapper {
        public String name;
        public String secret;
        public List<String> values;
    }
}
