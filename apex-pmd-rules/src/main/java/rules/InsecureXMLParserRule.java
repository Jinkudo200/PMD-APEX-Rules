package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

public class InsecureXMLParserRule extends AbstractApexRule {

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        String fullMethodName = node.getFullMethodName();
        if ("Dom.Document.load".equals(fullMethodName) || "Dom.Document.parse".equals(fullMethodName)) {
            setMessage("Insecure XML parser usage detected. Consider secure parsing options.");
            asCtx(data).addViolation(node);
        }
        return super.visit(node, data);
    }
}
