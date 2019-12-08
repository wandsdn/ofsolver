#!/usr/bin/env python

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
from parameterized import parameterized

from ofsolver.SAT import SplitSATSolver
from ._testcases import solvable_split, solvable_merged, solvable_untouched

solvable = solvable_split + solvable_merged + solvable_untouched


class TestSSATSolver(unittest.TestCase):

    def setUp(self):
        pass

    @parameterized.expand(solvable)
    def test_singlethreaded_solvable(self, name, ruleset, ttp):
        solver = SplitSATSolver(ttp, single=True,
                                log_level='ERROR', ttp_log_level='CRITICAL')
        ret = solver.solve(ruleset)
        self.assertIsNotNone(ret)

    @parameterized.expand(solvable)
    @unittest.skip("The multithreaded is unstable")
    def test_multithreaded_solvable(self, name, ruleset, ttp):
        solver = SplitSATSolver(ttp, single=False,
                                log_level='ERROR', ttp_log_level='CRITICAL')
        ret = solver.solve(ruleset)
        self.assertIsNotNone(ret)

if __name__ == "__main__":
    unittest.main()
