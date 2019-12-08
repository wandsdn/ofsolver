#!/usr/bin/env python
""" Loads the test cases used by the tests in this directory """

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


# Input Rulesets
RS_DIR = "./tests/rulesets/"
RS_OFCUPID = ("ofcupid", RS_DIR + "ofcupid.pickle")
RS_OFCUPID_VLAND = ("ofcupidvland", RS_DIR + "ofcupid.pickle.vland")
RS_SAMPLE_1 = ("rules1", RS_DIR + "sample_rules.pickle")
RS_SAMPLE_2 = ("rules2", RS_DIR + "sample_rules2.pickle")
RS_PARTIAL_TEST = ("partial", RS_DIR + "test_partial_merge.pickle")
RS_FWD_DROP = ("fwd_drop", RS_DIR + "test_fwd_drop.pickle")
RS_DROP_FWD = ("drop_fwd", RS_DIR + "test_drop_fwd.pickle")


# Target TTPs
TTP_DIR = "./tests/ttps/"
TTP_SINGLETABLE = ("singletable", TTP_DIR + "singletable.json")
TTP_OFDPA = ("ofdpa", TTP_DIR + "ofdpa-2.02-15-jun-2016.json.fixed")
TTP_TEST1 = ("pipeline1", TTP_DIR + "test_pipeline1.json")
TTP_TEST2 = ("pipeline2", TTP_DIR + "test_pipeline2.json")
TTP_FWD_DROP = ("fwd_drop", TTP_DIR + "test_fwd_drop.json")
TTP_DROP_FWD = ("drop_fwd", TTP_DIR + "test_drop_fwd.json")


# Solvable cases, lists of (name, ruleset, ttp)

def _create_match(rs, ttp):
    """ Takes a ruleset and ttp and returns (name, rs_path, ttp_path) """
    return rs[0] + "_" + ttp[0], rs[1], ttp[1]

""" These should simply fit into the pipeline as is. """
solvable_untouched = [
    _create_match(RS_SAMPLE_1, TTP_TEST2),
    _create_match(RS_SAMPLE_2, TTP_TEST1),
    _create_match(RS_OFCUPID, TTP_SINGLETABLE),
    _create_match(RS_OFCUPID_VLAND, TTP_OFDPA),
    _create_match(RS_FWD_DROP, TTP_FWD_DROP),
    _create_match(RS_DROP_FWD, TTP_DROP_FWD),
    ]

""" These are solvable with rules being placed as is or merged """
solvable_merged = [
    _create_match(RS_SAMPLE_1, TTP_TEST1),
    _create_match(RS_SAMPLE_1, TTP_SINGLETABLE),
    _create_match(RS_SAMPLE_2, TTP_SINGLETABLE),
    _create_match(RS_PARTIAL_TEST, TTP_SINGLETABLE),
    _create_match(RS_FWD_DROP, TTP_SINGLETABLE),
    _create_match(RS_DROP_FWD, TTP_SINGLETABLE),
    _create_match(RS_FWD_DROP, TTP_DROP_FWD),
    _create_match(RS_DROP_FWD, TTP_FWD_DROP),
    ]

""" These are solvable by splitting, merging or placing rules """
solvable_split = [
    _create_match(RS_SAMPLE_2, TTP_TEST2),
    ]
