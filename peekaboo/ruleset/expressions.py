###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         expressions.py                                                      #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2019  science + computing ag                             #
# Based on pyparsing's eval_arith.py.
# Copyright 2009, 2011 Paul McGuire
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or (at       #
# your option) any later version.                                             #
#                                                                             #
# This program is distributed in the hope that it will be useful, but         #
# WITHOUT ANY WARRANTY; without even the implied warranty of                  #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU           #
# General Public License for more details.                                    #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

""" A simple expression grammar used for writing generic rules. """

from future.builtins import super

import logging
import operator
import re
from pyparsing import nums, alphas, alphanums, Word, Combine, Suppress, \
    oneOf, opAssoc, infixNotation, Literal, Keyword, Group, \
    delimitedList, QuotedString, ParserElement, ParseException
from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)


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
        self.string_repr_format = "(%s)"

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

    def __str__(self):
        return self.string_repr_format % (
            " ".join(["%s" % x for x in self.token]))


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
                logger.debug("Regular expression match: %s == %s",
                             function, val)
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
    def __init__(self, token):
        super().__init__(token)
        self.string_repr_format = "[%s]"

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
    def __init__(self, token):
        super().__init__(token)
        self.string_repr_format = "{%s}"

    def eval(self, context):
        self.set_context(context)
        logger.debug("Set: %s", self.value)
        ret = set()
        for val in self.value:
            ret.add(self.subeval(val))
        if self.contains_regexes:
            return RegexSet(ret)
        return ret


class IdentifierMissingException(KeyError):
    pass


class EvalIdentifier(EvalBase):
    """ Class to evaluate a parsed object name """
    def eval(self, context):
        logger.debug("Identifier: %s", self.value)
        if 'member' in context and context['member']:
            return self.value

        try:
            return context['variables'][self.value]
        except KeyError as error:
            raise IdentifierMissingException(error.args[0])


class EvalResult(EvalBase):
    """ Class to evaluate a analysis result """
    def convert(self):
        logger.debug("Result: %s", self.token)
        result_map = {
            'fail': Result.failed,
            'ignore': Result.ignored,
        }

        if self.token in result_map:
            self.value = result_map[self.token]
        else:
            self.value = Result[self.token]


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


def operator_operands(tokenlist):
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
        for op, val in operator_operands(self.value[1:]):
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
                    ret = None
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

    @staticmethod
    def handle_regexes(function, val1, val2):
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
        for op, parseobj in operator_operands(self.value[1:]):
            val2 = self.subeval(parseobj)
            logger.debug("Comparison: %s %s %s", val1, op, val2)
            function = self.operator_map[op]
            if not self.handle_regexes(function, val1, val2):
                break
            val1 = val2
        else:
            return True

        return False


class ExpressionParser(object):
    """ Define and run the parser. """
    def __init__(self):
        # speed up infixNotation considerably at the price of some cache memory
        ParserElement.enablePackrat()

        boolean = Keyword('True') | Keyword('False')
        integer = Word(nums)
        real = Combine(Word(nums) + "." + Word(nums))
        string = (QuotedString('"', escChar='\\')
                  | QuotedString("'", escChar='\\'))
        regex = QuotedString('/', escChar='\\')
        identifier = Word(alphas, alphanums + '_')
        dereference = infixNotation(identifier, [
            (Literal('.'), 2, opAssoc.LEFT, EvalArith),
        ])
        result = (Keyword('bad') | Keyword('fail') | Keyword('good')
                  | Keyword('ignore') | Keyword('unknown'))
        rval = boolean | real | integer | string | regex | result | dereference
        rvallist = Group(Suppress('[') + delimitedList(rval) + Suppress(']'))
        rvalset = Group(Suppress('{') + delimitedList(rval) + Suppress('}'))
        operand = rval | rvallist | rvalset

        # parse actions replace the parsed tokens with an instantiated object
        # which we can later call into for evaluation of its content
        boolean.setParseAction(EvalBoolean)
        integer.setParseAction(EvalInteger)
        real.setParseAction(EvalReal)
        string.setParseAction(EvalString)
        regex.setParseAction(EvalRegex)
        identifier.setParseAction(EvalIdentifier)
        result.setParseAction(EvalResult)
        rvallist.setParseAction(EvalList)
        rvalset.setParseAction(EvalSet)

        identity_test = Keyword('is') + ~Keyword('not') | Combine(
            Keyword('is') + Keyword('not'), adjacent=False, joinString=' ')
        membership_test = Keyword('in') | Combine(
            Keyword('not') + Keyword('in'), adjacent=False, joinString=' ')
        comparison_op = oneOf('< <= > >= != == isdisjoint')
        comparison = identity_test | membership_test | comparison_op

        self.parser = infixNotation(operand, [
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

    def parse(self, expression):
        """ Parse an expression and return an object supporting evaluation of
        that expression against a context. """
        try:
            return self.parser.parseString(expression, parseAll=True)[0]
        except ParseException as parse_error:
            col = parse_error.col
            raise SyntaxError(
                "Expression parse error near character %d: %s>>%s<<%s" % (
                    parse_error.col, expression[0:col], expression[col],
                    expression[col+1:]))


if __name__ == '__main__':
    print(ExpressionParser().parse('foo == (bar - blub)'))
