# Imports

import operator
from typing import Any
import pandas as pd
from src.core.logger import logger

# Operators and precedence
arithmetic_ops = {
    "**": 6,
    "*": 5,
    "/": 5,
    "%": 5,
    "+": 4,
    "-": 4
}

comparison_ops = {
    "<": 3,
    "<=": 3,
    ">": 3,
    ">=": 3,
    "==": 3,
    "!=": 3,
    "IN": 3,
    "NOTIN": 3
}

logical_ops = {
    "AND": 2,
    "OR": 1
}

all_ops = arithmetic_ops | comparison_ops | logical_ops


def to_num(x) -> float | Any:
    try:
        return float(x)
    except ValueError:
        return x


def is_chained_comparison_expr(exp: str) -> bool:
    """This function checks if a provided expression is a chained comparison expression:

    Example:
        is_chained_comparison_expr("a < b < c") -> True

    Parameters:
        exp (str): The Expression to check.

    Returns:
        Whether the expression was chained comparison.
    """

    count = 0

    for token in exp.split():
        if token.upper() in comparison_ops:
            count += 1
            if count > 1:
                return True

    return False


def de_chain(l: list) -> list[Any]:
    """This function convert a chained comparison expression to a de-chained version.
    It takes input as a list and returns the converted expression as a list.

    Example:
        A chained expression: a < b < c
        can be passed in as a list: ['a', '<', 'b', '<' ,'c']

        It will be converted to a < b AND b < c
        and returned as: ['a', '<', 'b', 'AND', 'b', '<' ,'c']

    Parameters:
        l (list): Expression as a list.

    Returns:
        De-chained expression."""

    l_de_chained = []
    brackets = {"(", ")"}

    for i, token in enumerate(l):

        if token in brackets:
            l_de_chained.append(token)

        elif token in comparison_ops:
            if i >= 2 and l[i - 2] in comparison_ops:
                l_de_chained.append("AND")
                l_de_chained.append(l[i - 1])

            l_de_chained.append(token)

        else:
            l_de_chained.append(token)

    return l_de_chained


def split_expr(exp: str) -> list[Any]:
    """This function converts a str expression to a list of operands and operators.

    Example:
        An expression a + b < c

        Is converted to ['a', '+', 'b', '<', 'c']

    Parameters:
        exp (str): The expression to split.

    Returns:
        Split expression."""

    exp_lines_f = []

    for line in exp.strip().splitlines():

        t_f = [""]

        for token in line.split():

            token_u = token.upper()

            if token_u in all_ops:
                t_f.append(token_u)
                t_f.append("")
            else:
                t_f[-1] += token + " "


        t_f = [to_num(x.strip()) for x in t_f if x != ""]

        if is_chained_comparison_expr(line):
            t_f = de_chain(t_f)

        exp_lines_f.extend(t_f)

    return exp_lines_f


def infix_to_postfix(l: list) -> list[Any]:
    """This function converts an infix expression (given as a list) to a postfix expression (returned as a list).

    Example:
        An infix expression a + b * c

        Is converted to ['a', 'b', 'c', '*', '+']

    Parameters:
        l (list): The infix expression.

    Returns:
        Postfix expression."""

    precedence = all_ops
    right_associative = {"**", "NOT"}

    stack = []
    output = []

    for token in l:

        token_str = token.upper() if isinstance(token, str) else None

        if token_str == "(":
            stack.append(token)

        elif token_str == ")":

            while stack and stack[-1] != "(":
                output.append(stack.pop())

            if stack:
                stack.pop()

        elif token_str in precedence:

            curr_prec = precedence[token_str]

            while stack:

                top = stack[-1]
                top_str = top.upper() if isinstance(top, str) else top

                if top_str not in precedence:
                    break

                top_prec = precedence[top_str]

                if top_prec > curr_prec or (
                        top_prec == curr_prec and token_str not in right_associative):
                    output.append(stack.pop())
                else:
                    break

            stack.append(token)

        else:
            output.append(token)

    while stack:
        output.append(stack.pop())

    return output


def evaluate(l: list):
    """This function evaluates an expression provided as a list.
    It does not support variables, all values must be provided to it inside the expression.

    Meaning that 2 + 3 will work.

    But a + b won't (if these are variables)

    Input must be given as a list: ['2', '+', '3']

    Parameters:
        l (list): The expression

    Returns:
        The value obtained after evaluation."""

    operations = {
        "+": operator.add,
        "-": operator.sub,
        "*": operator.mul,
        "/": operator.truediv,
        "%": operator.mod,
        "**": operator.pow,
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
        "IN": lambda a, b: a.isin(b) if isinstance(a, pd.Series) else a in  b,
        "NOTIN": lambda a, b: ~a.isin(b) if isinstance(a, pd.Series) else a not in b,
        "AND": lambda a, b: a & b,
        "OR": lambda a, b: a | b
    }

    stack = []

    for token in l:

        token_str = token.upper() if isinstance(token, str) else ""

        if token_str == "NOT":

            if not stack:
                logger.error('Malformed expression: NOT missing operand.')
                raise ValueError("Malformed expression: NOT missing operand.")

            stack.append(not bool(stack.pop()))

        elif token_str in operations:

            if len(stack) < 2:
                logger.error(f'Malformed expression: {token} missing operands.')
                raise ValueError(f"Malformed expression: {token} missing operands.")

            right = stack.pop()
            left = stack.pop()

            stack.append(operations[token_str](left, right))

        else:

            if token_str == "TRUE":
                stack.append(True)

            elif token_str == "FALSE":
                stack.append(False)

            else:
                stack.append(token)

    if len(stack) != 1:
        logger.error('Malformed expression: Unbalanced operands and operators.')
        raise ValueError("Malformed expression: Unbalanced operands and operators.")

    return stack[0]


def compile_expr(exp: str):
    """This function compiles a str expression into a postfix list expression.

    Example:
        a + b -> ['a', 'b', '+']

    Parameters:
        exp (str): The expression to compile.

    Returns:
        Compiled expression."""
    exp_f = split_expr(exp)

    return infix_to_postfix(exp_f)

def bind_var_and_evaluate(exp_f: list, **kwargs):
    """This function takes in a compiled expression and parameters for it, and evaluates and returns the answer.

    Example:
        check("a + b", a=4, b=5) -> 9

    Parameters:
        exp_f (list): Expression List
        kwargs: Variables to be put in the expression.

    Returns:
        The value obtained after evaluation."""

    brackets = {"(", ")"}
    expr = exp_f.copy()

    for i, token in enumerate(expr):

        if (
                isinstance(token, str)
                and token not in all_ops
                and token not in brackets
        ):

            if token in kwargs:
                expr[i] = kwargs[token]
            else:
                logger.error(f'Parameter {token} not fulfilled')
                raise ValueError(f"Parameter {token} not fulfilled")

    return evaluate(expr)