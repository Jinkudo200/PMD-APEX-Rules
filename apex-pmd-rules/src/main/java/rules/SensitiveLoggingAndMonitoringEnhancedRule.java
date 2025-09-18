package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * SensitiveLoggingAndMonitoringEnhancedRule
 *
 * Detects risky logging and monitoring patterns in Salesforce Apex code.
 * Covers OWASP A09: Security Logging and Monitoring Failures.
 *
 * Risks:
 * - Logging of secrets (passwords, tokens, session IDs, API keys).
 * - System.debug statements exposing sensitive or PII data.
 * - Lack of log sanitization (direct string concatenation with sensitive fields).
 *
 * Recommendations:
 * - Never log credentials or tokens.
 * - Use Salesforce Shield Event Monitoring or custom audit logs instead.
 * - Mask values before logging when absolutely necessary.
 */
public class SensitiveLoggingAndMonitoringEnhancedRule extends AbstractApexRule {

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        // Detect System.debug(...)
        if ("debug".equals(node.getMethodName()) && node.getFullMethodName().contains("System")) {
            node.descendants(ASTLiteralExpression.class).forEach(lit -> {
                if (lit.isString()) {
                    String value = lit.getImage();

                    if (looksLikeSensitive(value)) {
                        asCtx(data).addViolation(node,
                            "Insecure logging detected: '" + value +
                            "'. Avoid exposing sensitive data in System.debug.");
                    }

                    if (looksLikePII(value)) {
                        asCtx(data).addViolation(node,
                            "Possible PII logged: '" + value +
                            "'. Ensure compliance with GDPR/CCPA.");
                    }
                }
            });
        }

        return super.visit(node, data);
    }

    private boolean looksLikeSensitive(String value) {
        return value.matches("(?i).*(password|secret|token|sessionid|apikey|authorization).*");
    }

    private boolean looksLikePII(String value) {
        return value.matches("(?i).*(ssn|creditcard|iban|email|phone).*");
    }
}
