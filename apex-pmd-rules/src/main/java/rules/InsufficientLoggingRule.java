package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

public class InsufficientLoggingRule extends AbstractApexRule {

    @Override
    public Object visit(ASTCatchClause node, Object data) {
        boolean hasDebug = node.descendants(ASTMethodCallExpression.class)
            .anyMatch(m -> "System.debug".equals(m.getMethodName()));
        if (!hasDebug) {
            setMessage("Catch block without logging detected.");
            asCtx(data).addViolation(node);
        }
        return super.visit(node, data);
    }
}
