package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTStatement;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * Detects insecure deserialization in Apex code.
 *
 * Detects:
 * - JSON.deserialize / deserializeUntyped / deserializeStrict usage on untrusted sources
 * - Usage of deserialized variables in sensitive APIs without validation
 */
public class InsecureDeserializationEnhancedRule extends AbstractApexRule {

    private final Set<String> deserializedVars = new HashSet<>();
    private final Set<String> validatedVars = new HashSet<>();

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // find deserialization calls
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {

            String methodName = call.getMethodName();
            String typeName = call.getDefiningType();

            if ("JSON".equals(typeName) &&
                    (methodName.startsWith("deserialize") || methodName.equals("deserializeUntyped") || methodName.equals("deserializeStrict"))) {

                ASTVariableExpression left = call.ancestors(ASTStatement.class)
                        .first()
                        .firstChild(ASTVariableExpression.class);

                if (left != null && left.getImage() != null) {
                    deserializedVars.add(left.getImage());
                } else if (isUntrustedArgument(call)) {
                    asCtx(data).addViolation(call, "Deserialization of untrusted input without validation.");
                }
            }

            // Mark variables as validated if called validateXYZ(var)
            if (methodName != null && methodName.toLowerCase().contains("validate")) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    if (v.getImage() != null) validatedVars.add(v.getImage());
                }
            }
        }

        // Check usage of deserialized variables in sensitive sinks
        for (ASTVariableExpression v : node.descendants(ASTVariableExpression.class)) {
            if (v.getImage() != null && deserializedVars.contains(v.getImage()) &&
                    !validatedVars.contains(v.getImage())) {

                ASTMethodCallExpression parentCall = v.ancestors(ASTMethodCallExpression.class).first();
                if (parentCall != null && isSensitiveSink(parentCall)) {
                    asCtx(data).addViolation(v, "Deserialized data used in sensitive operation without validation: "
                            + parentCall.getMethodName());
                }
            }
        }

        deserializedVars.clear();
        validatedVars.clear();
        return super.visit(node, data);
    }

    private boolean isUntrustedArgument(ASTMethodCallExpression call) {
        for (ASTMethodCallExpression inner : call.children(ASTMethodCallExpression.class)) {
            String def = inner.getDefiningType() == null ? "" : inner.getDefiningType();
            if ("RestContext".equals(def) || "HttpRequest".equals(def)) return true;
            String name = inner.getMethodName() == null ? "" : inner.getMethodName().toLowerCase();
            if ("apexpages".equals(def) && name.contains("getparameters")) return true;
        }
        return false;
    }

    private boolean isSensitiveSink(ASTMethodCallExpression call) {
        String type = call.getDefiningType() == null ? "" : call.getDefiningType();
        String name = call.getMethodName() == null ? "" : call.getMethodName();

        if ("Database".equals(type) && (name.equals("query") || name.equals("countQuery"))) return true;
        if ("System".equals(type) && name.equals("schedule")) return true;
        if ("HttpRequest".equals(type) && (name.equals("setBody") || name.equals("setEndpoint"))) return true;
        if (call.getImage() != null && call.getImage().contains("Database.insert")) return true;

        return false;
    }
}
