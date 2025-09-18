package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * Detects insecure deserialization of JSON in Apex classes.
 * Flags JSON.deserialize calls and usage of unvalidated deserialized variables.
 */
public class InsecureDeserializationEnhancedRule extends AbstractApexRule {

    private final Set<String> deserializedVars = new HashSet<>();
    private final Set<String> validatedVars = new HashSet<>();

    @Override
    public Object visit(ASTUserClass node, Object data) {

        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String type = call.getFullMethodName(); // e.g., JSON.deserialize

            if (type.startsWith("JSON.deserialize") || type.startsWith("JSON.deserializeUntyped") || type.startsWith("JSON.deserializeStrict")) {

                // Walk up to find the assigned variable
                ApexNode<?> parent = call.getParent();
                while (parent != null) {
                    if (parent instanceof ASTVariableExpression) {
                        ASTVariableExpression varExpr = (ASTVariableExpression) parent;
                        deserializedVars.add(varExpr.getImage());
                        break;
                    } else if (parent instanceof ASTVariableDeclaration) {
                        ASTVariableDeclaration decl = (ASTVariableDeclaration) parent;
                        ASTVariableExpression varExpr = decl.firstChild(ASTVariableExpression.class);
                        if (varExpr != null) {
                            deserializedVars.add(varExpr.getImage());
                        }
                        break;
                    }
                    parent = parent.getParent();
                }

                // Flag direct literals passed to deserialize
                for (ASTLiteralExpression lit : call.descendants(ASTLiteralExpression.class)) {
                    asCtx(data).addViolation(call, "Insecure deserialization detected without validation.");
                }
            }

            // Simple heuristic for validation calls
            if (type.toLowerCase().contains("validate")) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    validatedVars.add(v.getImage());
                }
            }
        }

        // Flag deserialized vars used without validation
        for (ASTVariableExpression v : node.descendants(ASTVariableExpression.class)) {
            if (deserializedVars.contains(v.getImage()) && !validatedVars.contains(v.getImage())) {
                asCtx(data).addViolation(v, "Deserialized variable used without validation: " + v.getImage());
            }
        }

        deserializedVars.clear();
        validatedVars.clear();
        return super.visit(node, data);
    }
}
