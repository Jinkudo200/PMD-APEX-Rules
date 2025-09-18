package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * Detects command injection and unsafe schedule execution in Apex.
 * Flags untrusted variables used in System.schedule, Database.executeBatch,
 * or dynamic string methods like String.format / String.escapeSingleQuotes.
 */
public class CommandInjectionAndScheduleRule extends AbstractApexRule {

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

        // Step 2: Detect unsafe schedule/command usage
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String methodName = call.getMethodName();

            // System.schedule / Database.executeBatch
            if ("System.schedule".equals(methodName) || "Database.executeBatch".equals(methodName)) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    if (taintedVars.contains(v.getImage())) {
                        setMessage("Potential command injection: untrusted variable '" + v.getImage() + "' used in scheduling/batch.");
                        asCtx(data).addViolation(v);
                    }
                }
            }

            // Dynamic string usage
            if ("String.format".equals(methodName) || "String.escapeSingleQuotes".equals(methodName)) {
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    if (taintedVars.contains(v.getImage())) {
                        setMessage("Potential command injection via dynamic string: '" + v.getImage() + "'.");
                        asCtx(data).addViolation(v);
                    }
                }
            }
        }

        return super.visit(node, data);
    }
}
