package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

public class HardcodedSecretsAndNamedCredentialsRule extends AbstractApexRule {

    @Override
    public Object visit(ASTLiteralExpression node, Object data) {
        if (node.isString()) {
            String value = node.getImage();

            if (looksLikeSecret(value)) {
                asCtx(data).addViolation(node, 
                    "Hardcoded secret detected: '" + value + "'. Use Named Credentials or Protected Custom Metadata.");
            }

            if (looksLikeApiKey(value)) {
                asCtx(data).addViolation(node, 
                    "Hardcoded API key detected. Use Protected Custom Metadata or Named Credentials.");
            }
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        // Detect HttpRequest.setEndpoint("https://...")
        if ("setEndpoint".equals(node.getMethodName()) 
                && node.getFullMethodName().contains("HttpRequest")) {

            node.descendants(ASTLiteralExpression.class).forEach(lit -> {
                if (lit.isString()) {
                    asCtx(data).addViolation(node,
                        "HttpRequest.setEndpoint called with hardcoded endpoint. Use Named Credentials.");
                }
            });
        }
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTFieldDeclaration node, Object data) {
        node.descendants(ASTLiteralExpression.class).forEach(lit -> {
            if (lit.isString() && looksLikeSecret(lit.getImage())) {
                asCtx(data).addViolation(node,
                    "Hardcoded secret in field. Use Protected Custom Metadata / Named Credentials.");
            }
        });
        return super.visit(node, data);
    }

    private boolean looksLikeSecret(String value) {
        return value.matches("(?i).*(password|secret|token|apikey|authorization).*");
    }

    private boolean looksLikeApiKey(String value) {
        return value.matches("[A-Za-z0-9_\\-]{20,}");
    }
}
