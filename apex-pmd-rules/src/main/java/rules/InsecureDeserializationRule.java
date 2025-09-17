package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

public class InsecureDeserializationRule extends AbstractApexRule {

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        String fullMethodName = node.getFullMethodName();
        if ("JSON.deserialize".equals(fullMethodName)) {
            setMessage("Unvalidated JSON.deserialize call detected.");
            asCtx(data).addViolation(node);
        }
        return super.visit(node, data);
    }
}