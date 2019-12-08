""" Helper functions for boolean expressions using SATisPy

Additionally, sets up the SATisPy library for better performance.
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
import operator
import itertools
from six.moves import reduce

from bidict import bidict
import satispy
# Disable the optimisation reduction
# This just uses CPU cycles for little gain
satispy.cnf.cnfClass = satispy.cnf.NaiveCnf
from satispy import Variable
from satispy.cnf import cnfClass as Cnf
from satispy.solver import Minisat

Variable.__repr__ = Variable.__str__

def reduce_or(items, default=Cnf()):
    """ Reduce a list of Variables or Cnfs to a single Cnf using the logical
        and.
        items: A list of Variables or Cnf expressions
        default: The default to set if not None, if None an exception is
                 raised in the case of an empty list
    """
    if default is not None and not items:
        return default
    return reduce(operator.or_, items)


def reduce_and(items, default=Cnf()):
    """ Reduce a list of Variables or Cnfs to a single Cnf using the logical
        and.
        items: A list of Variables or Cnf expressions
        default: The default to set if not None, if None an exception is
                 raised in the case of an empty list
    """
    if default is not None and not items:
        return default

    builder = set()
    for item in items:
        if isinstance(item, Variable):
            builder.add(frozenset([item]))
        else:
            builder |= item.dis

    ret = Cnf()
    ret.dis = frozenset(builder)
    return ret


def reduce_onehot(items, default=Cnf()):
    """ Ensures exactly one SAT clause in items is set to True
        items: A list of variables or cnf expressions
        default: Will be returned if the list is empty
    """
    at_least_one = reduce_or(items, default=default)
    return at_least_one & reduce_AMO(items, default=default)


def reduce_AMO(items, default=Cnf()):
    """ Ensures at most one SAT clause in items is set to True """
    if not items:
        return default
    cnf = Cnf()
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
        for y, z in itertools.combinations([-i for i in items], 2):
            cnf &= (y | z)
    return cnf


def reduce_AMO_binary(items, _assign_id=[0]):
    """ At most one 'binary' encoding (Prestwich) aka. 'bitwise'

        Example (where a-d are items; X1-X2 are extra variables):
        -a|-X1   -b| X1   -c|-X1   d|X1
        -a|-X2   -b|-X2   -c| X1   d|X1

        As soon a var is set True ~var becomes False so the X clause must
        become True. This forces all X's to a value of either True of False.
        In the case of a this is b1=False b2=False which can be shortened to
        00, b set true becomes 01, c 10, d 11. I.e. increasing binary
        numbers, which are unique; therefore will conflict if two vars are
        set to True.

        Clauses: n * log2(n)
        Extra Vars: log2(n)
        Only sees a win over naive with 8+ vars. 7 is equal.

        items: A list of variables, or cnfs (must have two or more items)
        assign_id: Internal counter, don't replace

        NOTE: This method is less efficient than sequential and product.
              However in-case something matters in the future.
    """
    mask = 1
    nitems = [-i for i in items]
    cnf = Cnf()
    # 8 items mask
    while (mask << 1) < len(items):
        v = Variable("BIN" + str(_assign_id[0]))
        _assign_id[0] += 1
        nv = -v
        for i in range(len(items)):
            if i & mask:
                cnf &= nitems[i] | v
            else:
                cnf &= nitems[i] | nv
        mask <<= 1
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

    cnf = Cnf()
    i = 0  # Iterate item counter
    for vp in ps:
        for vq in qs:
            if i >= len(items):
                break
            cnf &= (nitems[i] | vp) & (nitems[i] | vq)
            i += 1
    return reduce_AMO(ps) & reduce_AMO(qs) & cnf


def to_dimacs(b_expr, mapping=None):
    if mapping is None:
        mapping = bidict()
    clauses = []
    s = []
    if isinstance(b_expr, Variable):
        b_expr.dis = frozenset([frozenset([b_expr])])
    for clause in b_expr.dis:
        for v in clause:
            if v.name not in mapping:
                mapping[v.name] = len(mapping) + 1
            s.append((b"-" if v.inverted else b"") +
                     str(mapping[v.name]).encode('ascii'))
        clauses.append(b" ".join(s))
        del s[:]
    return clauses, mapping


def variable_name(v):
    return v.name
