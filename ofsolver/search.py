#!/usr/bin/python
""" An early approach to rule-fitting

The search solver searches for a valid way to place an input rule
into the previous solution, one rule at a time. As such it
can not find solutions where two rules depend on each other being there
to create the correct forwarding.

The search solver only considers merging rules, not splitting rules.

Search solver maintains a list of all valid solutions as it performs
a breadth first search.

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

from __future__ import print_function
import functools
import timeit

import six
from six import viewitems, viewvalues
from tqdm import tqdm

from ofequivalence.ruleset import single_table_condense
from .solver import (Solver, Solution, Rule, to_single_table_scaled, normalise,
                     TTPFlow, SOLVER_LOGGER, find_single_table, check_solution,
                     Match, rule_from_ttp, BadOverlap,
                     simulate_reachability, get_best_solution)


time_copy = 0
time_considered = 0
time_checking = 0

# (Left, right) -> Blah
# Where left is a list and right a single rule
cache_merged = {}


def generate_merged_solutions(sln, flw, needs_merge, can_merge):
    needs = [x for x in needs_merge if x[1] is flw]
    # parents = set([x[0] for x in needs])
    # if set(flw.parents) != parents:
    #     print "Special case, oh what to do..."
    #     debug()
    #     pass
    global cache_merged

    for x in needs:
        if id(x[0]) in sln.merged_left:
            cache_key = (id(flw), tuple(sln.merged_left[id(x[0])]))
            merged = cache_merged.get(cache_key, None)
            if merged is None:
                merged = []
                for a in sln.merged_left[id(x[0])]:
                    res = a.merge(flw)
                    res.priority += flw.priority
                    res.instructions.goto_table = a.instructions.goto_table
                    merged.append(res)
                merged = tuple(merged)
                cache_merged[cache_key] = merged
            if id(flw) in sln.merged_left:
                sln.merged_left[id(flw)] += merged
            else:
                sln.merged_left[id(flw)] = list(merged)
            for merge in merged:
                sln._add(merge, overwrite=True)
            # Just add this on the end
            # sln.placements += merged

    # Verify valid output
    for x in sln._placements.values():
        assert isinstance(x, Rule)
        assert isinstance(x.priority, six.integer_types)
        assert isinstance(x.table, six.integer_types)


def generate_merged_solutions_1(sln, flw, needs_merge, can_merge):
    needs = [x for x in needs_merge if x[1] is flw]
    # parents = set([x[0] for x in needs])
    # if set(flw.parents) != parents:
    #     print "Special case, oh what to do..."
    #     debug()
    #     pass

    for x in needs:
        if id(x[0]) in sln.merged_left:
            merged = []
            for a in sln.merged_left[id(x[0])]:
                res = a.merge(flw)
                res.priority += flw.priority
                res.instructions.goto_table = a.instructions.goto_table
                merged.append(res)
            if id(flw) in sln.merged_left:
                sln.merged_left[id(flw)] += merged
            else:
                sln.merged_left[id(flw)] = list(merged)
            # Just add this on the end
            sln.placements += tuple(merged)

    # Verify valid output
    for x in sln.placements:
        assert isinstance(x, Rule)
        assert isinstance(x.priority, six.integer_types)
        assert isinstance(x.table, six.integer_types)

def to_single_table(self):
    """ Return this solution as a single table equivalence """
    # Fill tables with default actions, * -> []
    if self._cache_single_table is not None:
        return self._cache_single_table
    tables = set()
    for x in self._placements:
        tables.add(x[1])
    m0 = Rule().match.get_wildcard()
    for table in tables:
        if (m0, table) not in self._placements:
            f = Rule()
            f.priority = 0
            f.table = table
            self.add([f], None)
    ruleset = list(self._placements.values())
    self._cache_single_table = to_single_table_scaled(ruleset)
    return to_single_table_scaled(ruleset)

def do_check(orig_sln, Pfrw, considered, frw, nsingle_Sw, requires_merge,
             can_merge):
    global time_copy
    global time_considered
    global time_checking
    res = set()
    # orig_sln = Pw[orig_sln]

    for new_sln in Pfrw:
        s1 = timeit.default_timer()
        # We need to consider priority order XXX
        # Ensure all rules are included - put in a low priority drop
        try:
            merged_sln = orig_sln.copy_and_add(new_sln, frw, overwrite=True)
            generate_merged_solutions(merged_sln, frw, requires_merge,
                                      can_merge)
        except BadOverlap:
            # No this does not work
            continue
        finally:
            time_copy += timeit.default_timer() - s1
        s1 = timeit.default_timer()
        if merged_sln in considered:
            continue
        time_considered += timeit.default_timer() - s1
        s1 = timeit.default_timer()

        # Move rules to table0 because rules might not be in table 0 yet.
        # We assume rules added later will direct packets to hit these rules.
        intable0 = []
        for rule in merged_sln.get_ordered_rules():
            if rule.table != 0:
                if (Rule().match.get_wildcard(), 0) not in merged_sln._placements:
                    cpy = rule.copy()
                    cpy.table = 0
                    intable0.append(cpy)

        # No rules, add a default drop
        if len(merged_sln) == 0:
            intable0 = [Rule(priority=0, table=0)]
        check_sln = merged_sln.copy_and_add(intable0, None)

        import py_global_debug
        # Set mark 
        #set_mark(273)
        if check_solution(check_sln, nsingle_Sw):
            res.add(merged_sln)
        considered.add(merged_sln)
        time_checking += timeit.default_timer() - s1
        # Check Solution is valid!!? #
    return res


def create_yield_list(Pw, frw, Pfrw, res_list, can_merge, requires_merge):
    """ Generates (yields) a list of solutions, and creates a list of those
        created.
        Pw: The possible working solutions (so far)
        frw: The flow rule we are adding
        Pfrw: The combinations of placements for that rule
        res_list: Where the resulting list should be stored
    """
    for orig_sln in Pw:
        for new_sln in Pfrw:
            # We need to consider priority order XXX
            # Ensure all rules are included - put in a low priority drop
            merged_sln = orig_sln.copy_and_add(new_sln, frw, overwrite=True)
            generate_merged_solutions(merged_sln, frw, requires_merge,
                                      can_merge)
            merged_sln.number = len(res_list)
            res_list.append(merged_sln)
            blah = []
            for x in viewvalues(merged_sln.placements):
                blah.append(x.copy())
            try:
                reach = simulate_reachability(blah)
                for k, v in viewitems(reach):
                    if v is None:
                        debug()
                    if v == Match():
                        debug()
            except Exception:
                # debug()
                # print "ARRG"
                pass
            yield merged_sln
            # if merged_sln in considered:
            #     continue


class SearchSolver(Solver):
    """ Adds rules in all possible locations and does a space scan.
        This might not quite cover the entire search space, as solutions are
        considered by adding a single rule each time and that partial solution
        is evaluated against that portion of the original.
    """

    def run_solver(self, Si, all_solutions, Si_single_table, Si_normalised):
        Solver.run_solver(self, Si, all_solutions, Si_single_table, Si_normalised)

        self.compute_direct_placements(Si)

        # The working portion of the original solution, i.e. the portion we
        # are currently considering, this is the inverse of Si - Sr
        Sw = []
        # Sr the remaining portion of the solution that has not been considered
        # We seed it with the entire initial rule set
        Sr = list(Si)

        requires_merge, can_merge = find_single_table(Si, self.deps)

        # These are full solutions - I.e. a number of placement rules
        Pw = [Solution()]
        # for x in Pw:
        #    res = ttp.try_place_rules(x[0].table, x[0])
        #    # Pick shortest path
        #    # For ofdpa we will pick a path via table 10
        #    for k in res:
        #        if 10 in k:
        #            for a in res[k]:
        #                # Just pick the first that works
        #                # Ignore the TTPFlows as these are built in
        #                if isinstance(a[0], Rule):
        #                    x.append(a[0])
        #            break
        # We could verify behaviour early with all fixed rules but lets just do
        # that at the end and also worry about reachability then?

        # Merge each with built-ins so the result works in simulation

        for x in Pw:
            for f in self.ttp.collect_children(TTPFlow):
                # Exclude egress tables
                if f.built_in and f.parent.number <= 60:
                    res = rule_from_ttp(f)
                    res.built_in = True
                    x.add([res], None, overwrite=True)

        # Special single table optimisation case
        if len(self.ttp.get_tables()) == 1:
            pass

        iteration = 0
        # Now we consider adding another rule
        for frw in self.consider_order:
            if self.progress:
                print("Adding: ", frw)
            Sr.remove(frw)
            Sw.append(frw)  # XXX should we be sorting this?
            Sw.sort(key=lambda x: -x.priority)
            single_Sw = to_single_table_scaled(Sw)
            single_Sw.append(Rule(priority=0, table=0))
            nsingle_Sw = normalise(single_Sw)

            Pfrw = frw.placements

            # These are full solutions - I.e. a number of placement rules
            Pfrw = [[x] for x in Pfrw]

            # Merge, rules?
            """ Merging rules, combining 2 tables into 1 (recursively if needed)

            When?
            Say you have rules a and b
            Table 1           | Table 2
            ---------------------------------
            a : goto table(b) | b
                              |
            In the solution a and b fit in the same table, but not at the same
            time i.e. a is installed and b fails, but b would succeed without a

            Or more generally if a and b can be merged and fit in a table
            """
            to_merge = [x for x in requires_merge if x[0] == frw]

            for existing, new in to_merge:
                new.path = (new,)
                condensed = single_table_condense([existing], [new], new.table)
                assert len(condensed) == 1

            # Merge the solutions
            Pn = set()

            if Pw:
                # Well it might already be covered
                Pfrw.append([])
                # considered = set()
                # Pn = []
                if not self.single:
                    tpool = self.ThreadPool(8)
                    input_list = []
                    func = functools.partial(check_solution, target=nsingle_Sw)
                    o_set = 0
                    generator = tpool.imap(func,
                                           create_yield_list(Pw, frw, Pfrw,
                                                             input_list,
                                                             can_merge,
                                                             requires_merge))
                    if self.progress:
                        generator = tqdm(generator, total=len(Pw)*len(Pfrw))
                    for res in generator:
                        if res is True:
                            Pn.add(input_list[o_set])
                        o_set += 1
                    tpool.terminate()
                else:
                    func = functools.partial(do_check, Pfrw=Pfrw,
                                             considered=set(), frw=frw,
                                             nsingle_Sw=nsingle_Sw,
                                             requires_merge=requires_merge,
                                             can_merge=can_merge)
                    generator = Pw
                    if self.progress:
                        generator = tqdm(generator)
                    for x in generator:
                        Pn |= func(x)
                pass

            if len(Pn) == 0:
                SOLVER_LOGGER.warning("Could not find a solution")
                SOLVER_LOGGER.warning("Failed to fit rule %s", frw)
                added = [str(x) for x in Sw if x is not frw]
                SOLVER_LOGGER.warning("Already added:\n%s", "\n".join(added))
                return None

            Pw = Pn
            if len(Pw) > 200:
                Pw = set(list(Pw)[0:200])
            iteration += 1
            if self.progress:
                print("Iteration:", iteration)
                print("Solution Size:", len(Pw))
                print("Time copy:", time_copy, "consider:",
                      time_considered, "checking:", time_checking)

        if len(Pw):
            solution = get_best_solution(Pw)

        return solution
