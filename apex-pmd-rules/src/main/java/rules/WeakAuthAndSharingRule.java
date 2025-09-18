package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * Detects Apex classes without 'with sharing' and weak authentication practices.
 * OWASP Category: Broken Access Control / Security Misconfiguration
 */
public class WeakAuthAndSharingRule extends AbstractApexRule {

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // Check if class declaration contains 'with sharing'
        boolean hasWithSharing = node.getImage() != null && node.getImage().toLowerCase().contains("with sharing");
        if (!hasWithSharing) {
            setMessage("Apex class does not use 'with sharing'. This may cause privilege escalation.");
            asCtx(data).addViolation(node);
        }

        // Detect hardcoded passwords in string literals
        for (ASTLiteralExpression lit : node.descendants(ASTLiteralExpression.class)) {
            if (lit.isString() && lit.getImage().matches("(?i).*(password|passwd|secret).*")) {
                setMessage("Hardcoded password detected. Avoid storing secrets in code.");
                asCtx(data).addViolation(lit);
            }
        }

        // Optional: Detect weak auth method calls (example: compare password with ==)
        for (ASTMethodCallExpression m : node.descendants(ASTMethodCallExpression.class)) {
            if (m.getMethodName() != null && m.getMethodName().toLowerCase().contains("compare")) {
                setMessage("Potential weak authentication logic detected.");
                asCtx(data).addViolation(m);
            }
        }

        return super.visit(node, data);
    }
}
