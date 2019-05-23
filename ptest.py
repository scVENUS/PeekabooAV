#!/usr/bin/env python

# PoC for generic rules evaluating sample and report properties
# based on pyparsing's eval_arith.py
# Copyright 2009, 2011 Paul McGuire

from future.builtins import super

import logging
import operator
import re
from pyparsing import nums, alphas, alphanums, Word, Combine, Suppress, \
    oneOf, opAssoc, infixNotation, Literal, Keyword, Group, \
    delimitedList, QuotedString, ParserElement, ParseException

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class EvalBase(object):
    """ Base class of evaluatable objects providing common infrastructure. """
    def __init__(self, tokens):
        """ Just store the tokens for later evaluation. Expects all relevant
        tokens to be grouped together in the first element of the token list
        passed. This is the default for operand+operator+operand+... constructs
        with infixNotation and can be forced for others using Group():

        rvallist = Group(Suppress('[') + delimitedList(rval) + Suppress(']'))
        """
        self.value = self.token = tokens[0]
        self.context = None
        self.convert()

    def convert(self):
        """ Method to (optionally) convert the input token(s) into something
        else. Particularly used for conversion to base types. """
        self.value = self.token

    def feedback(self, info):
        """ Accept and process feedback evaluation children. """
        # by default propagate feedback upwards if we have a context
        if self.context and 'parent' in self.context:
            self.context['parent'].feedback(info)

    def subeval(self, expression, update=None):
        """ Evaluate a subexpression with an updated evaluation context
        containing common metadata such as that we're it's parent and optional
        additional data. """
        context = self.context.copy()
        context['parent'] = self
        if update:
            context.update(update)
        return expression.eval(context)

    def set_context(self, context):
        """ Save an evaluation context internally for later use by e.g.
        feedback(). """
        self.context = context

    def eval(self, context):
        """ Evaluate the object content against a context. Just return the
        stored (and optionally converted) value by default and remember our
        context for possible feedback to our parent or from our children. """
        self.set_context(context)
        return self.value


class EvalBoolean(EvalBase):
    """ Class to evaluate a parsed boolean constant """
    def convert(self):
        logger.debug("Boolean: %s", self.value)
        self.value = self.token == "True"


class EvalInteger(EvalBase):
    """ Class to evaluate a parsed integer constant """
    def convert(self):
        logger.debug("Integer: %s", self.token)
        self.value = int(self.token)


class EvalReal(EvalBase):
    """ Class to evaluate a parsed real constant """
    def convert(self):
        logger.debug("Real: %s", self.token)
        self.value = float(self.token)


class EvalString(EvalBase):
    """ Class to evaluate a parsed string constant """
    def convert(self):
        logger.debug("String: %s", self.token)
        self.value = self.token


class OperatorRegex(object):
    """ A class implementing operators on regular expressions. """
    def __init__(self, string):
        self.regex = re.compile(string)

    @staticmethod
    def compare_op_impl(function, other):
        """ Implement handling of iterable operands. """
        if isinstance(other, (list, set)):
            for val in other:
                logger.debug("Regular expression match: %s == %s", function, val)
                if function(val):
                    return True
            return False

        return function(other)

    def __eq__(self, other):
        """ Implement equality using re.match """
        logger.debug("Regular expression match: %s == %s", self.regex, other)
        return self.compare_op_impl(self.regex.match, other)

    def __contains__(self, other):
        """ Implement membership using re.search """
        logger.debug("Regular expression search: %s in %s", self.regex, other)
        return self.compare_op_impl(self.regex.search, other)


class EvalRegex(EvalBase):
    """ Class to evaluate a regular expression """
    def convert(self):
        logger.debug("Regular expression: %s", self.token)
        self.value = OperatorRegex(self.token)

    def eval(self, context):
        self.set_context(context)
        self.feedback({'regex_parsed': True})
        return self.value


class RegexIterableMixIn(object):
    """ Common functionality for lists and sets containing regular expressions
    with different behaviour of membership operators. """
    def __eq__(self, other):
        if not isinstance(other, (list, set)):
            other = [other]

        # in contrast to normal lists, a list of regexes compared to a list
        # of strings is considered equal if any regex matches any string
        for regex in self:
            logger.debug("Eval regex: %s == %s", regex, other)
            if regex == other:
                return True

        return False

    def __contains__(self, item):
        for regex in self:
            logger.debug("Eval regex: %s in %s", regex, item)
            # we implement "regex in string" of our grammar as "string in
            # regex" so that our overridden operator
            # regex.__contains__(string) is called and searching can be
            # done. Otherwise error "TypeError: 'in <string>' requires
            # string as left operand, not OperatorRegex" would ensue.
            if item in regex:
                return True

        return False


class RegexList(RegexIterableMixIn, list):
    """ A list containing regular expressions with different behaviour of
    membership operators. """


class RegexSet(RegexIterableMixIn, set):
    """ A set containing regular expressions with different behaviour of
    membership operators. """


class EvalRegexIterableMixIn(object):
    """ Common functionality for iterables which may contain regular
    expressions. """
    def __init__(self, tokens):
        super().__init__(tokens)
        self.contains_regexes = False

    def feedback(self, info):
        """ Mark this object as containing regular expressions if a child
        object reports so in its feedback to us. """
        if 'regex_parsed' in info:
            self.contains_regexes = True
            del info['regex_parsed']

        super().feedback(info)


class EvalList(EvalRegexIterableMixIn, EvalBase):
    """ Class to evaluate a parsed list """
    def eval(self, context):
        self.set_context(context)
        logger.debug("List: %s", self.value)
        ret = []
        for val in self.value:
            ret.append(self.subeval(val))
        if self.contains_regexes:
            return RegexList(ret)
        return ret


class EvalSet(EvalRegexIterableMixIn, EvalBase):
    """ Class to evaluate a parsed list """
    def eval(self, context):
        self.set_context(context)
        logger.debug("Set: %s", self.value)
        ret = set()
        for val in self.value:
            ret.add(self.subeval(val))
        if self.contains_regexes:
            return RegexSet(ret)
        return ret


class EvalIdentifier(EvalBase):
    """ Class to evaluate a parsed object name """
    def eval(self, context):
        logger.debug("Identifier: %s", self.value)
        if 'member' in context and context['member']:
            return self.value

        return context['variables'][self.value]


class EvalModifier(EvalBase):
    """ Class to evaluate typical single-operand modifier expressions such as
    explicit sign change, bitwise and logical not. """
    def __init__(self, tokens):
        super().__init__(tokens)
        self.operator, self.value = tokens[0]

    def eval(self, context):
        self.set_context(context)
        val = self.subeval(self.value)
        if self.operator == '+':
            return val
        elif self.operator == '-':
            return -val
        elif self.operator == '~':
            return ~val
        elif self.operator == 'not':
            return not val

        raise ValueError('Invalid operator %s' % self.operator)


class EvalPower(EvalBase):
    """ Class to evaluate exponentiation expressions """
    def eval(self, context):
        self.set_context(context)
        res = self.subeval(self.value[-1])
        for val in self.value[-3::-2]:
            res = self.subeval(val)**res

        return res


def OperatorOperands(tokenlist):
    """ Generator to extract operators and operands in pairs """
    iterator = iter(tokenlist)
    while True:
        try:
            yield (next(iterator), next(iterator))
        except StopIteration:
            break


class EvalArith(EvalBase):
    """ Class to evaluate typical arithmetic and bitwise operations like
    addition, multiplication, division and shifts expressions. Operator
    precedence is handled by the order in which they're evaluated by the
    parser, i.e. given to infixNotation. """
    def eval(self, context):
        self.set_context(context)
        ret = self.subeval(self.value[0])
        for op, val in OperatorOperands(self.value[1:]):
            if op == '+':
                ret += self.subeval(val)
            elif op == '-':
                ret -= self.subeval(val)
            elif op == '*':
                ret *= self.subeval(val)
            elif op == '/':
                ret /= self.subeval(val)
            elif op == '//':
                ret //= self.subeval(val)
            elif op == '%':
                ret %= self.subeval(val)
            elif op == '<<':
                ret <<= self.subeval(val)
            elif op == '>>':
                ret >>= self.subeval(val)
            elif op == '.':
                ret = getattr(ret, self.subeval(val, update={'member': True}))
            elif op == "->":
                if ret:
                    ret = self.subeval(val)
                else:
                    ret = "unknown"
            else:
                raise ValueError('Invalid operator %s' % op)

        return ret


class EvalLogic(EvalBase):
    """ Class to evaluate comparison expressions """
    def __init__(self, tokens):
        super().__init__(tokens)
        self.operator_map = {
            "<": operator.lt,
            "<=": operator.le,
            ">": operator.gt,
            ">=": operator.ge,
            "==": operator.eq,
            "!=": operator.ne,
            "in": EvalLogic.in_,
            "not in": EvalLogic.not_in,
            "is": operator.is_,
            "is not": operator.is_not,
            "isdisjoint": lambda a, b: a.isdisjoint(b),
            "and": operator.and_,
            "or": operator.or_,
        }

    @staticmethod
    def in_(a, b):
        """ Literally implement membership test. Make it a static method so we
        can do identity checks. Do not use operator.contains because it needs
        operands swapped. """
        return a in b

    @staticmethod
    def not_in(a, b):
        """ Naively implement non-membership test. """
        return a not in b

    def handle_regexes(self, function, val1, val2):
        """ Special handling of equality and membership checks for regular
        expressions. """
        if (function in (operator.eq, operator.ne)
                and isinstance(val2, (OperatorRegex, RegexIterableMixIn))):
            # swap operands around in case the first does not contain any regex
            # but the other does to reliably reroute to our overridden __eq__
            # operator, just do that always to keep checks simple since
            # (in)equality is commutative anyway
            val1, val2 = val2, val1
        elif (function in (EvalLogic.in_, EvalLogic.not_in)
              and isinstance(val1, (OperatorRegex, RegexIterableMixIn))):
            # "<regex> in <string>|<list-of-strings>" of our grammar directly
            # implemented using the "in" operator would call
            # <string>|<list-of-strings>.__contains__(<regex>) which we cannot
            # override with reasonable effort. To get a call of
            # <regex>.__contains__(<string>|<list-of-strings>) we need to
            # switch operands. Otherwise error "TypeError: 'in <string>'
            # requires string as left operand, not OperatorRegex" would ensue.
            val1, val2 = val2, val1

        # nothing special
        return function(val1, val2)

    def eval(self, context):
        self.set_context(context)
        val1 = self.subeval(self.value[0])
        for op, parseobj in OperatorOperands(self.value[1:]):
            val2 = self.subeval(parseobj)
            logger.debug("Comparison: %s %s %s", val1, op, val2)
            function = self.operator_map[op]
            if not self.handle_regexes(function, val1, val2):
                break
            val1 = val2
        else:
            return True

        return False


class Sample(object):
    """ A dummy sample. """
    def __init__(self, a, b):
        self.a = a
        self.b = b


class Report(object):
    """ A dummy report. """
    def __init__(self, a, c):
        self.a = a
        self.__c = c

    @property
    def signatures(self):
        """ Some dummy signatures. """
        return ['ra', 'ri', 'reari']

    @property
    def c(self):
        """ c """
        return self.__c


def main():
    """ Define and run the parser. """
    # speed up infixNotation considerably at the price of some cache memory
    ParserElement.enablePackrat()

    boolean = Keyword('True') | Keyword('False')
    integer = Word(nums)
    real = Combine(Word(nums) + "." + Word(nums))
    string = QuotedString('"', escChar='\\') | QuotedString("'", escChar='\\')
    regex = QuotedString('/', escChar='\\')
    identifier = Word(alphas, alphanums + '_')
    dereference = infixNotation(identifier, [
        (Literal('.'), 2, opAssoc.LEFT, EvalArith),
    ])
    rval = boolean | real | integer | string | regex | dereference
    rvallist = Group(Suppress('[') + delimitedList(rval) + Suppress(']'))
    rvalset = Group(Suppress('{') + delimitedList(rval) + Suppress('}'))
    operand = rval | rvallist | rvalset

    # parse actions replace the parsed tokens with an instantiated object which
    # we can later call into for evaluation of its content
    boolean.setParseAction(EvalBoolean)
    integer.setParseAction(EvalInteger)
    real.setParseAction(EvalReal)
    string.setParseAction(EvalString)
    regex.setParseAction(EvalRegex)
    identifier.setParseAction(EvalIdentifier)
    rvallist.setParseAction(EvalList)
    rvalset.setParseAction(EvalSet)

    identity_test = Keyword('is') + ~Keyword('not') | Combine(
        Keyword('is') + Keyword('not'), adjacent=False, joinString=' ')
    membership_test = Keyword('in') | Combine(
        Keyword('not') + Keyword('in'), adjacent=False, joinString=' ')
    comparison_op = oneOf('< <= > >= != == isdisjoint')
    comparison = identity_test | membership_test | comparison_op

    expression = infixNotation(operand, [
        (Literal('**'), 2, opAssoc.LEFT, EvalPower),
        (oneOf('+ - ~'), 1, opAssoc.RIGHT, EvalModifier),
        (oneOf('* / // %'), 2, opAssoc.LEFT, EvalArith),
        (oneOf('+ -'), 2, opAssoc.LEFT, EvalArith),
        (oneOf('<< >>'), 2, opAssoc.LEFT, EvalArith),
        (Literal('&'), 2, opAssoc.LEFT, EvalArith),
        (Literal('^'), 2, opAssoc.LEFT, EvalArith),
        (Literal('|'), 2, opAssoc.LEFT, EvalArith),
        (comparison, 2, opAssoc.LEFT, EvalLogic),
        (Keyword('not'), 1, opAssoc.RIGHT, EvalModifier),
        (Keyword('and'), 2, opAssoc.LEFT, EvalLogic),
        (Keyword('or'), 2, opAssoc.LEFT, EvalLogic),
        (Keyword('->'), 2, opAssoc.LEFT, EvalArith),
    ])

    rules = [
        '(sample1.a - sample2.b) == 0',
        '(sample2.a - report1.c) == 9',
        'sample2.a - sample2.b / 2',
        '(sample2.a - sample2.b) / 5',
        'sample2.a in [5, 7]',
        'sample2.a not in [sample2.a, 7]',
        'sample1.a is sample1.a',
        'sample1.a is not sample2.a',
        '{sample1.a, 5, "10"} == {sample2.a }',
        '1 >= 0 and 2 <= 1 or 5>=1 and True',
        '/re/ != ["ra", "re"]',
        '/ri/ != ["ra", "rarera"]',
        '/re/ in ["ra", "re"]',
        '/ri/ not in ["ra", "rarera"]',
        '[/ra/, /re/] in report1.signatures -> "bar"',
    ]

    context = {
        'variables': {
            'sample1': Sample(10, 5),
            'sample2': Sample(11, 6),
            'report1': Report(1, 2),
            'report2': Report(3, 4),
        },
    }

    for rule in rules:
        try:
            ret = expression.parseString(rule, parseAll=True)
        except ParseException as parse_error:
            col = parse_error.col
            logger.error(
                "Expression parse error near character %d: %s>>%s<<%s",
                parse_error.col, rule[0:col], rule[col], rule[col+1:])
            break

        print(ret)
        print(rule, ret[0].eval(context))

if __name__ == '__main__':
    main()
