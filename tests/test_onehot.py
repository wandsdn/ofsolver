#!/usr/bin/env python
""" Test that onehot is working correctly.

    We check all combinations making this take about 30 secs
    to run.
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

import unittest
import itertools
from ofsolver.util.satispy import (reduce_onehot, Variable,
                                   Minisat, reduce_and)


class TestSatispy(unittest.TestCase):

    def setUp(self):
        pass

    def test_onehot_naive(self):
        solver = Minisat()
        """ Test the naive case, trigged when less than or equal 5 """
        vs = [Variable(str(i)) for i in range(5)]
        cnf_base = reduce_onehot(vs)

        # Check turning all off fails
        cnf = cnf_base & reduce_and([-v for v in vs])
        solution = solver.solve(cnf)
        self.assertFalse(solution.success)

        # Check turning one on works and finds a solution
        for v in vs:
            cnf = cnf_base & reduce_and([-_v for _v in vs if _v != v])
            cnf &= v
            solution = solver.solve(cnf)
            self.assertTrue(solution.success)

        # Check every combination of two fails
        for a, b in itertools.combinations(vs, 2):
            cnf = cnf_base & a & b
            solution = solver.solve(cnf)
            self.assertFalse(solution.success)


    def test_onehot_sequential(self):
        solver = Minisat()
        """ Test the seq case, trigged when less than 25 and >=6 """
        vs = [Variable(str(i)) for i in range(15)]
        cnf_base = reduce_onehot(vs)

        # Check turning all off fails
        cnf = cnf_base & reduce_and([-v for v in vs])
        solution = solver.solve(cnf)
        self.assertFalse(solution.success)

        # Check turning one on works and finds a solution
        for v in vs:
            cnf = cnf_base & reduce_and([-_v for _v in vs if _v != v])
            cnf &= v
            solution = solver.solve(cnf)
            self.assertTrue(solution.success)

        # Check every combination of two fails
        for a, b in itertools.combinations(vs, 2):
            cnf = cnf_base & a & b
            solution = solver.solve(cnf)
            self.assertFalse(solution.success)


    def test_onehot_product(self):
        solver = Minisat()
        """ Test the product case, trigged when >=25 """
        vs = [Variable(str(i)) for i in range(150)]
        cnf_base = reduce_onehot(vs)

        # Check turning all off fails
        cnf = cnf_base & reduce_and([-v for v in vs])
        solution = solver.solve(cnf)
        self.assertFalse(solution.success)

        # Check turning one on works and finds a solution
        for v in vs:
            cnf = cnf_base & reduce_and([-_v for _v in vs if _v != v])
            cnf &= v
            solution = solver.solve(cnf)
            self.assertTrue(solution.success)

        # Check every combination of two fails
        for a, b in itertools.combinations(vs, 2):
            cnf = cnf_base & a & b
            solution = solver.solve(cnf)
            self.assertFalse(solution.success)


if __name__ == '__main__':
    unittest.main()
