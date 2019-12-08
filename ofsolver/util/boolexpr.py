""" Helper functions for boolean expressions using the boolexpr library.

Additionally, provides an interface compatiable with SATisPy.

Boolexpr tends to perform worse than SATisPy.
"""

# Copyright 2019 Richard Sanger, Wand Network Research Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
import math

from bidict import bidict
from boolexpr import Context, array, ONE, onehot0
import boolexpr

Kind = boolexpr.BoolExpr.Kind
boolexpr.BoolExpr.__neg__ = boolexpr.BoolExpr.__invert__
boolexpr.BoolExpr.__rshift__ = boolexpr.impl

ctx = Context()
Variable = ctx.get_var


def reduce_or(items, default=ONE):
    if default is not None and not items:
        return default
    return array(items).or_reduce()


def reduce_and(items, default=ONE):
    if default is not None and not items:
        return default
    return array(items).and_reduce()


def reduce_onehot(items, default=ONE):
    if default is not None and not items:
        return default
    return reduce_or(items) & reduce_AMO(items)


def to_dimacs(b_expr, mapping=None):
    """ Convert a expression to the DIMACS format
        b_expr: The Boolean Expression
        mapping: Optional, existing mapping to reuse

        return (DIMACS, mapping):
            DIMACS: The DIMACS format string
            mapping: Mapping of variables to DIMACS strings
    """
    # Ast has format (And, item, item, ...)
    #        item = (Or, var, var, var)
    if mapping is None:
        # The initial version has implies, etc which to_cnf() does
        # not handle well, tseytin adds extra variables to keep it simplier
        # By default these are named a_*
        cnf_ast = b_expr.simplify().tseytin(ctx).to_ast()
        mapping = bidict()
    else:
        cnf_ast = b_expr.to_cnf().to_ast()


    clauses = []
    s = []
    if cnf_ast[0] != Kind.and_:
        assert cnf_ast[0] in (Kind.or_, Kind.var, Kind.comp)
        cnf_ast = (Kind.and_, cnf_ast)
    for clause in cnf_ast[1:]:
        if clause[0] != Kind.or_:
            assert clause[0] in (Kind.var, Kind.comp)
            clause = (Kind.or_, clause)
        for v in clause[1:]:
            if v[2] not in mapping:
                mapping[v[2]] = len(mapping) + 1
            if v[0] == Kind.comp:
                s.append(b"-" + str(mapping[v[2]]).encode('ascii'))
            else:
                assert v[0] == Kind.var
                s.append(str(mapping[v[2]]).encode('ascii'))
        clauses.append(b" ".join(s))
        del s[:]
    return (clauses, mapping)


def variable_name(v):
    return str(v)


def reduce_AMO(items, default=ONE):
    """ Ensures at most one SAT clause in items is set to True """
    if not items:
        return default
    if len(items) >= 25:
        cnf = reduce_AMO_product(items)
    elif len(items) >= 6:
        cnf = reduce_AMO_sequential(items)
    else:
        # The naive algorithm piecewise algorithm
        # (A1 | A2 | ... | An)
        # & (-A1 | -A2) & (-A1 | -A2) & ... & (-A1 | -An)
        # & (-A2 | -A3) & ... & (-A2 | -An)
        # & ...
        # & (-An-1 | An)
        return onehot0(*items)
    return cnf


def reduce_AMO_sequential(items, _assign_id=[0]):
    """ At most one 'sequential' encoding (Sinz)

        Based on count-and-compare hardware.

        Example (where a-d are items; X1-X2 are extra variables):
        ~a | X1
        ~b | X2 & ~X1 | X2 & ~b | ~X1 (repeat)
        ~c | ~X2

        Setting a to True, forces X1 to be True. X1 as True X2 to true and b
        to false. Thus propagating as X2 to True forces c to False.

        items: A list of variables, or cnfs (must have two or more items)
        _assign_id: Internal counter, don't replace
    """
    nitems = [-i for i in items]
    extra_vars = []
    nextra_vars = []
    for _ in range(len(items)-1):
        v = Variable("SEQ" + str(_assign_id[0]))
        extra_vars.append(v)
        nextra_vars.append(-v)
        _assign_id[0] += 1
    cnf = (nitems[0] | extra_vars[0]) & (nitems[-1] | nextra_vars[-1])
    for i in range(1, len(items)-1):
        cnf &= ((nitems[i] | extra_vars[i]) &
                (nextra_vars[i-1] | extra_vars[i]) &
                (nitems[i] | nextra_vars[i-1]))
    return cnf


def reduce_AMO_product(items, _assign_id=[0]):
    """ At most one 'product' encoding (Chen)

        Which I believe to be the best, once a large number is involved >25

        Assign each var to a point in a p*q grid, (Pi, Qj).
        Forcing that value of Pi and Qi to be True. Each point will differ
        by either P or Q (or both).
        As such this can be applied recursively, by allowing at most one
        of the P's and one of the Q's to be set. Once the number of P or Q is
        small, another encoding can be used.

        items: A list of variables, or cnfs (must have two or more items)
        _assign_id: Internal counter, don't replace
    """
    # Find two numbers p, q such that p*q >= len(items)
    p = int(math.ceil(math.sqrt(len(items))))
    if p * (p-1) >= len(items):
        q = p-1
    else:
        q = p
    assert p*q >= len(items)
    # Allocate variables for q and p
    qs = []
    ps = []
    nitems = [-i for i in items]
    for _ in range(q):
        qs.append(Variable("PRD" + str(_assign_id[0])))
        _assign_id[0] += 1
    for _ in range(p):
        ps.append(Variable("PRD" + str(_assign_id[0])))
        _assign_id[0] += 1

    cnf = []
    i = 0  # Iterate item counter
    for vp in ps:
        for vq in qs:
            if i >= len(items):
                break
            cnf.append((nitems[i] | vp))
            cnf.append((nitems[i] | vq))
            i += 1
    return reduce_AMO(ps) & reduce_AMO(qs) & reduce_and(cnf)
