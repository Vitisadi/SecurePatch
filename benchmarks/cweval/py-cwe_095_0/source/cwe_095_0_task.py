def evaluate_expression_unsafe(expr: str) -> str:
    try:
        return str(eval(expr))
    except:
        return ''


evaluate_expression = evaluate_expression_unsafe
