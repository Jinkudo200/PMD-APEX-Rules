package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

public class DeprecatedMethodsRule extends AbstractApexRule {

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        String fullMethodName = node.getFullMethodName();
        if (fullMethodName != null && fullMethodName.toLowerCase().matches(".*(md5|sha1).*")) {
            setMessage("Usage of deprecated or insecure library method detected.");
            asCtx(data).addViolation(node);
        }
        return super.visit(node, data);
    }
}
