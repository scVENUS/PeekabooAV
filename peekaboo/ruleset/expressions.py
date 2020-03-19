###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         expressions.py                                                      #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2020  science + computing ag                             #
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
        self.convert()

    def convert(self):
        """ Method to (optionally) convert the input token(s) into something
        else. Particularly used for conversion to base types. """
        self.value = self.token

    def eval(self, context):
        """ Evaluate the object content against a context. Just return the
        stored (and optionally converted) value by default. """
        return self.value

    def is_implication(self):
        """ To be implemented by subclasses to determine if they ultimately are
        implications. """
        return False

    def __str__(self):
        return "%s" % self.token


class EvalBoolean(EvalBase):
    """ Class to evaluate a parsed boolean constant """
    def convert(self):
        logger.debug("Boolean: %s", self.value)
        self.value = self.token == "True"


class EvalNone(EvalBase):
    """ Class to evaluate a parsed none constant """
    def convert(self):
        logger.debug("None: %s", self.value)
        self.value = None


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

    def __str__(self):
        return '"%s"' % self.token


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

        if other is None:
            return False

        return function(other)

    def __eq__(self, other):
        """ Implement equality using re.match """
        logger.debug("Regular expression match: %s == %s", self.regex, other)
        return self.compare_op_impl(self.regex.match, other)

    def __ne__(self, other):
        """ Implement inequality using re.match """
        logger.debug("Regular expression match: %s != %s", self.regex, other)
        return not self.compare_op_impl(self.regex.match, other)

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
        return self.value

    def __str__(self):
        return "/%s/" % self.token


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

    def __ne__(self, other):
        return not self == other

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


class EvalList(EvalBase):
    """ Class to evaluate a parsed list """
    def eval(self, context):
        logger.debug("List: %s", self.value)
        ret = []
        regexes = False
        for val in self.value:
            element = val.eval(context)
            if isinstance(element, OperatorRegex):
                regexes = True
            ret.append(element)
        if regexes:
            return RegexList(ret)
        return ret

    def __str__(self):
        return "[%s]" % (", ".join(["%s" % x for x in self.token]))

class EvalSet(EvalBase):
    """ Class to evaluate a parsed set """
    def eval(self, context):
        logger.debug("Set: %s", self.value)
        ret = set()
        regexes = False
        for val in self.value:
            element = val.eval(context)
            if isinstance(element, OperatorRegex):
                regexes = True
            # For our use case None being an element of a set() is of no use
            # and highly confusing. Supress it
            if element is None:
                continue
            ret.add(element)
        if regexes:
            return RegexSet(ret)
        return ret

    def __str__(self):
        return "{%s}" % (", ".join(["%s" % x for x in self.token]))


class IdentifierMissingException(KeyError):
    def __init__(self, name):
        super().__init__("Identifier '%s' is missing" % name)
        self.name = name


class EvalIdentifier(EvalBase):
    """ Class to evaluate a parsed object name """
    def eval(self, context):
        logger.debug("Identifier: %s", self.value)

        # return the literal identifier name if dereferencing it is disabled
        if isinstance(context, dict) and not context.get('deref', True):
            return self.value

        # potentially raise an actual KeyError here to not mask it as missing
        # identifier
        variables = context['variables']
        try:
            # look the identifier up in the variables part of the context
            return variables[self.value]
        except KeyError as error:
            raise IdentifierMissingException(self.value)


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
        val = self.value.eval(context)
        if self.operator == '+':
            return val
        elif self.operator == '-':
            return -val
        elif self.operator == '~':
            return ~val
        elif self.operator == 'not':
            return not val

        raise ValueError('Invalid operator %s' % self.operator)

    def __str__(self):
        return "(%s%s)" % (self.operator, self.value)


class EvalPower(EvalBase):
    """ Class to evaluate exponentiation expressions """
    def eval(self, context):
        res = self.value[-1].eval(context)
        for val in self.value[-3::-2]:
            res = val.eval(context)**res

        return res

    def __str__(self):
        return "(%s)" % (" ".join(["%s" % x for x in self.token]))


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
        ret = self.value[0].eval(context)
        for op, val in operator_operands(self.value[1:]):
            if op == '+':
                ret += val.eval(context)
            elif op == '-':
                ret -= val.eval(context)
            elif op == '*':
                ret *= val.eval(context)
            elif op == '/':
                ret /= val.eval(context)
            elif op == '//':
                ret //= val.eval(context)
            elif op == '%':
                ret %= val.eval(context)
            elif op == '<<':
                ret <<= val.eval(context)
            elif op == '>>':
                ret >>= val.eval(context)
            elif op == '&':
                ret &= val.eval(context)
            elif op == '^':
                ret ^= val.eval(context)
            elif op == '|':
                ret |= val.eval(context)
            elif op == '.':
                # expect op to be an identifier, have it return its name by
                # setting deref to False and then resolve that property in
                # current ret by calling getattr() on it
                property_context = context.copy()
                property_context['deref'] = False
                property_name = val.eval(property_context)
                ret = getattr(ret, property_name)
            elif op == "->":
                if ret:
                    ret = val.eval(context)
                else:
                    ret = None
            else:
                raise ValueError('Invalid operator %s' % op)

        return ret

    def is_implication(self):
        """ Determines if this object is ultimately an implication. """
        try:
            return self.value[-2] == '->'
        except KeyError:
            return False

    def __str__(self):
        return "(%s)" % (" ".join(["%s" % x for x in self.token]))


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
        val1 = self.value[0].eval(context)
        for op, parseobj in operator_operands(self.value[1:]):
            val2 = parseobj.eval(context)
            logger.debug("Comparison: %s %s %s", val1, op, val2)
            function = self.operator_map[op]
            if not self.handle_regexes(function, val1, val2):
                break
            val1 = val2
        else:
            return True

        return False

    def __str__(self):
        return "(%s)" % (" ".join(["%s" % x for x in self.token]))


class ExpressionParser(object):
    """ Define and run the parser. """
    def __init__(self):
        # speed up infixNotation considerably at the price of some cache memory
        ParserElement.enablePackrat()

        boolean = Keyword('True') | Keyword('False')
        none = Keyword('None')
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
        rval = boolean | none | real | integer | string | regex | result | dereference
        rvallist = Group(Suppress('[') + delimitedList(rval) + Suppress(']'))
        rvalset = Group(Suppress('{') + delimitedList(rval) + Suppress('}'))
        operand = rval | rvallist | rvalset

        # parse actions replace the parsed tokens with an instantiated object
        # which we can later call into for evaluation of its content
        boolean.setParseAction(EvalBoolean)
        none.setParseAction(EvalNone)
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
