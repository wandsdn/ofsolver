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
from ofequivalence.rule import (Rule, ActionList, Group, Match,
                                Instructions, ActionSet)
from ofsolver.solver import simulate_actions

class TestSimulateActions(unittest.TestCase):
    def setUp(self):
        self.f = Rule()
        self.fg1 = Group()
        self.fg1.type_ = 'INDIRECT'
        self.fg1.buckets = [ActionList([("OUTPUT", 7)])]

        self.fg2 = Group()
        self.fg2.type_ = 'INDIRECT'
        self.fg2.buckets = [ActionList(
            [("POP_MPLS", 0x800), ("OUTPUT", 8)])]
        self.act_apply1 = ActionList(
            [('GROUP', self.fg1), ("SET_FIELD", ("ETH_DST", 0x1002)), ("OUTPUT", 1)])

        self.act_apply2 = ActionList(
            [("SET_FIELD", ("ETH_DST", 0x1002)), ("OUTPUT", 4), ('GROUP', self.fg2)])

        self.act_set1 = ActionSet(
            [("SET_FIELD", ("IPV4_SRC", 123)), ("OUTPUT", 5)])

        self.act_set2 = ActionSet(
            [("SET_FIELD", ("IPV4_SRC", 321)), ("POP_VLAN", None), ("OUTPUT", 6)])

        self.inst1 = Instructions()
        self.inst1.apply_actions = self.act_apply1
        self.inst1.write_actions = self.act_set1

        self.inst2 = Instructions()
        self.inst2.apply_actions = self.act_apply2
        self.inst2.write_actions = self.act_set2


    def test_equal_matches(self):
        matcha = Match([("VLAN_VID", 0x1001, None)])
        matchb = Match([("VLAN_VID", 0x1001, None)])

        f1 = Rule(priority=100, match=matcha, instructions=self.inst1, table=1)
        f2 = Rule(priority=100, match=matcha, instructions=self.inst2, table=2)

        res = simulate_actions(f1, f2)
        self.assertEqual(res[0], None)
        # act_apply1 + act_apply2 + merge(act_set1, act_set2)
        self.assertEqual(res[1],
            ActionList(self.act_apply1+self.act_apply2+(self.act_set1+self.act_set2)))
        self.assertEqual(res[2], None)

        print(self.act_set1)
        print(self.act_set2)
        print(self.act_set1 + self.act_set2)


if __name__ == "__main__":
    unittest.main()
