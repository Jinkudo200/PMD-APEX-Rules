package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * Detects SOQL injection vulnerabilities in Apex code.
 * Flags untrusted variables used in dynamic Database.query or Database.countQuery calls.
 */
public class SoqlInjectionTaintRule extends AbstractApexRule {

    @Override
    public Object visit(ASTUserClass node, Object data) {

        Set<String> taintedVars = new HashSet<>();

        // Step 1: Collect variables from untrusted sources
        for (ASTVariableExpression var : node.descendants(ASTVariableExpression.class)) {
            String name = var.getImage();
            if (name != null && name.toLowerCase().matches(".*(input|param|restcontext|apexpages).*")) {
                taintedVars.add(name);
            }
        }

        // Step 2: Detect dynamic SOQL usage
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String methodName = call.getMethodName();
            if ("Database.query".equals(methodName) || "Database.countQuery".equals(methodName)) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    if (taintedVars.contains(v.getImage())) {
                        setMessage("Potential SOQL injection: untrusted variable '" + v.getImage() + "' used in dynamic query.");
                        asCtx(data).addViolation(v);
                    }
                }
            }
        }

        return super.visit(node, data);
    }
}
