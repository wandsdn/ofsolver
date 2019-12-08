""" Provides util functions """

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

from itertools import chain, combinations


def all_combinations(i, min_len=0):
    """ Returns a generator of all possible combinations of any length
        i: An iterable input with length, such as a list
        min_len: The minimum length of the returned combinations, default 0
    """
    return chain.from_iterable(
        combinations(i, r) for r in range(min_len, len(i)+1))
