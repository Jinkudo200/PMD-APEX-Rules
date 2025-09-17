package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

public class HardcodedSecretsRule extends AbstractApexRule {

    @Override
    public Object visit(ASTLiteralExpression node, Object data) {
        // Vérifie si c'est une chaîne de caractères
        if (node.isString()) {
            String literal = node.getImage(); // ou getValue() selon ta version
            if (literal.matches("(?i).*(apikey|secret|token|passwd).*")) {
                setMessage("Hardcoded secret, API key, password, or token found.");
                asCtx(data).addViolation(node);
            }
        }
        return super.visit(node, data);
    }
}
