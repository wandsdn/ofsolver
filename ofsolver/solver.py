#!/usr/bin/python
""" The base solver class which actual solvers inherit from

    This provides useful functions to the solver and the
    basic solver layout.
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
import itertools
from itertools import chain
import traceback
import operator
import logging
from collections import defaultdict

from six.moves import reduce
from six import viewitems, viewvalues, itervalues
from tqdm import tqdm

from ttp_tools.TTP import TableTypePattern, TTPFlow
# Magic loading of the satisfies part of the library
import ttp_tools.ttp_satisfies
from ttp_tools.ttp_satisfies import Remaining

from ofequivalence.convert_ttp import rule_from_ttp
from ofequivalence.rule import (ActionSet, Rule, Match, MergeException)
from ofequivalence.ruleset import (node_to_tree,
                                   scale_ruleset, to_single_table_scaled,
                                   sort_ruleset)
from ofequivalence.ruleset_deps_direct import build_ruleset_deps
from ofequivalence.headerspace import wildcard_intersect
from ofequivalence.convert_ryu import ruleset_from_ryu, UnpicklingError
from ofequivalence.convert_fib import ruleset_from_fib
from ofequivalence.normalisebdd import (normalise, check_equal,
                                        find_conflicting_paths)
from .util import all_combinations
from .util.timer import TimerHierarchy, OneShotTimer, time_func

"""
Solver Logger, logging of state during the solver process.
CRITICAL: An internal error has occurred, likely making the result invalid
ERROR: An internal error which can be recovered from
WARNING: Logs information about why a failure occurred
INFO: Sparely used to notify if something cannot be placed etc, however is not
      the reason for failure.
DEBUG: Debug information, such as when counters are added, or size at points
       during the solver.

"""
SOLVER_LOGGER = logging.getLogger("Solver")
SOLVER_LOGGER.setLevel(logging.WARNING)

Rule.__repr__ = lambda x: str(x) + '\n'
# tqdm Has a background monitor thread which takes 10seconds to cleanup
# This can be too long and result in running out of threads
# This disables it
tqdm.monitor_interval = 0


def find_table_restrictions(left, rnum):
    """ Find if some bits must always be a given value to hit a table """
    collected_wc = []
    for l in left:
        if l.instructions.goto_table == rnum:
            collected_wc.append(l.get_goto_egress())
    if not collected_wc:
        return None
    res = reduce(lambda a, b: a.union_cover(b), collected_wc)
    return res


def simulate_reachability(flows, initial_restriction=Match()):
    """ Simulates a flattened version of which packets can reach
        another rule and therefore be output.

        This wont detect all cases, however will detect cases in which
        individual bits must be a specific value. Great for finding
        that we always have a vlan on a given rule. Or only this port hits
        it.

        Returns a dict mapping flow to (ingress, egress) pairs
                If an ingress is None a rule is unreachable, otherwise it is
                the portion of traffic that will hit the rule.
                If an egress is None a rule does not goto anywhere, or has not
                traffic hitting it.
    """
    ret = {}
    tables = {f.table for f in flows}
    if not flows:
        return {}
    assert 0 in tables
    tables.remove(0)

    table0_fs = [f for f in flows if f.table == 0]
    table0_fs = sorted(table0_fs, key=lambda f: -f.priority)
    for flow in table0_fs:
        for check_flow in [f for f in table0_fs if f.priority > flow.priority]:
            # Check that we are not obviously covered by higher priority rules
            # We could even mask this with possible traffic XXX
            if flow.match.issubset(check_flow.match):
                # We are not hit
                ret[flow] = (None, None)
                break
        else:
            ingress = initial_restriction.intersection(flow.match)
            egress = None
            if flow.instructions.goto_table is not None:
                egress = flow.get_goto_egress(ingress=ingress)
            ret[flow] = (ingress, egress)

    for table in tables:
        next_table_flows = [f for f in flows if f.table == table]
        next_table_flows = sorted(next_table_flows, key=lambda f: -f.priority)
        for flow in next_table_flows:
            for check_flow in [f for f in next_table_flows
                               if f.priority > flow.priority]:
                # Check that its not obviously covered by higher priority rules
                # We could even mask this with possible traffic XXX
                if flow.match.issubset(check_flow.match):
                    # We are not hit
                    ret[flow] = (None, None)
                    break
            else:
                # Now collect everything going to this
                collected = []
                for k, v in viewitems(ret):
                    if (k.table < flow.table and
                            k.instructions.goto_table == table):
                        if v[1] is not None:
                            # We have some input, but does it overlap?
                            if v[1].overlaps(flow.match):
                                collected.append(
                                    v[1].intersection(flow.match))
                if not collected:
                    ret[flow] = (None, None)
                    continue
                ingress = reduce(lambda a, b: a.union_cover(b), collected)
                egress = None
                if flow.instructions.goto_table is not None:
                    egress = flow.get_goto_egress(ingress=ingress)
                ret[flow] = (ingress, egress)

    return ret


def simulate_actions(flowa, flowb):
    """ Returns the actions applied to packets reaching both rules

        flowa: The first flow
        flowb: The second flow
        return: (actionsa, actionsab, actionsb) - Note in the case a packet
                matches a and b it may hit both rules or only one.
    """
    same_table = flowa.table == flowb.table
    acomes_first = flowa.table < flowb.table or (
        same_table and flowa.priority > flowb.priority)
    # Assert it is not ambiguous as to which has priority
    assert not (same_table and flowa.priority == flowb.priority)

    # We only care about the instructions now
    flowa_m = flowa.match
    flowb_m = flowb.match
    flowa = flowa.instructions
    flowb = flowb.instructions

    actionsa = None
    actionsab = None
    actionsb = None

    # Things that only hit a or b are the same no matter what
    actionsa = flowa.full_actions()
    actionsb = flowb.full_actions()

    if same_table:
        # Simulate a single table, for the overlapping case
        # Only the highest priority rule is hit
        if acomes_first:
            actionsab = actionsa
        else:
            actionsab = actionsb
    else:
        # Simulate two tables
        if not acomes_first:
            # Make sure a comes first
            flowa, flowb = flowb, flowa
        action_set = ActionSet()
        if not flowb.clear_actions:
            action_set += flowa.write_actions
        action_set += flowb.write_actions

        # Now lets merge these all together
        actionsab = flowa.apply_actions + flowb.apply_actions
        actionsab += action_set

    if flowa_m.issubset(flowb_m):
        # There is no portion hitting only flowa, it is ab
        actionsa = None
    if flowb_m.issubset(flowa_m):
        # There is no portion hitting only flowb it is ab
        actionsb = None

    # TODO remove duplicates, e.g. set_field 1, set_field 2
    return (actionsa, actionsab, actionsb)


def try_clear_actions(location, orig, resultant):
    """ Checks that the location supports clear actions and updates the
        resultant with this information
        location: The TTPFlow
        orig: The original Rule
        resultant: The installable rule
        return: True (and an updated resultant) else false
    """
    if resultant.instructions.clear_actions:
        return True
    # Just try this
    if 'CLEAR_ACTIONS' in [x.instruction for x in
                           location.instruction_set.get_flat()]:
        print("Looks good, we are doing a delayed installation")
        resultant.instructions.clear_actions = True
        saved = orig.instructions.clear_actions
        orig.instructions.clear_actions = True
        # if next(itervalues(location._satisfies(orig))) != resultant:
        # assert next(itervalues(location._satisfies(orig))) == resultant
        orig.instructions.clear_actions = saved
        return True
    return False


def actions_check_overlapping(orig, override):
    """ Tests if override's action set will override orig's

        This does not compare apply_actions

        orig: The original (first) Rule
        override: The overriding (second) Rule
        return True or False
    """
    orig_set = ActionSet(orig.instructions.write_actions)
    for x in override.instructions.write_actions:
        orig_set.append(x[0], x[1])

    if orig_set == override.instructions.write_actions:
        return True
    else:
        # TODO Resolve group + output case
        # Group takes priority, output is ignored
        # This is odd, because they are different in the set
        # i.e. a group will not overwrite an output nor output a group
        # Meaning that adding a output to a packet directed to a group is a nop
        return False


def simulated_equals(l, r):
    if l[0] is None:
        if r[0] is not None:
            return False
    elif not l[0].equiv_equal(r[0]):
        return False
    if l[1] is None:
        if r[1] is not None:
            return False
    elif not l[1].equiv_equal(r[1]):
        return False
    if l[2] is None:
        if r[2] is not None:
            return False
    elif not l[2].equiv_equal(r[2]):
        return False

    return True


def get_possible_dependency_placement(parent, child):
    """ Find where any two nodes can be placed which are dependent on each
        other.
        parent: The parent Rule (node)
        child: The child Rule (node)
        return: A set of
                ((parent_rule, parent_location), (child_rule, child_location))
                objects
    """
    rets = set()
    counter = 0
    for cloc in child.possible_locations:
        cinst = next(itervalues(cloc._satisfies(child)))
        for ploc in parent.possible_locations:

            counter += 1
            pinst = next(itervalues(ploc._satisfies(parent)))
            # TODO we need to check the location also works for getting
            # traffic too and from it.

            # Lets check that the parent comes first? As it did originally.
            # Note this is not entirely true if the input mixes write with
            # apply this can be a lot more complex
            # Maybe we should just simulate the case and see if the results are
            # the same

            # The original actions taken
            orig_actions = simulate_actions(parent, child)

            # Check if this works directly
            def do_check():
                new_actions = simulate_actions(pinst, cinst)
                if simulated_equals(orig_actions, new_actions):
                    rets.add(((pinst, ploc), (cinst, cloc)))
                # try and clear the parents action set
                elif (not parent.instructions.clear_actions and
                      try_clear_actions(ploc, parent, pinst)):
                    new_actions = simulate_actions(pinst, cinst)
                    if simulated_equals(orig_actions, new_actions):
                        rets.add(((pinst, ploc), (cinst, cloc)))
                    elif (not child.instructions.clear_actions and
                          try_clear_actions(cloc, child, cinst)):
                        new_actions = simulate_actions(pinst, cinst)
                        if simulated_equals(orig_actions, new_actions):
                            rets.add(((pinst, ploc), (cinst, cloc)))
                        else:
                            print("No luck on this one")
                        cinst.instructions.clear_actions = None
                    pinst.instructions.clear_actions = None
                elif (not child.instructions.clear_actions and
                      try_clear_actions(cloc, child, cinst)):
                    new_actions = simulate_actions(pinst, cinst)
                    if simulated_equals(orig_actions, new_actions):
                        rets.add(((pinst, ploc), (cinst, cloc)))
                    else:
                        print("No luck on this one")
                    cinst.instructions.clear_actions = None
                else:
                    print("No luck on this one")

            # make sure the priority order is correct
            do_check()

            if (not rets and pinst.priority < cinst.priority and
                    ploc.priority is None and cloc.priority is None):
                # Try swapping priorities
                pinst.priority, cinst.priority = cinst.priority, pinst.priority
                parent.priority, child.priority = (child.priority,
                                                   parent.priority)
                do_check()
                parent.priority, child.priority = (child.priority,
                                                   parent.priority)

            print(counter, child)
            print(counter, parent)
            print(counter, cinst)
            print(counter, pinst)
            continue

    return rets

def filter_less_specific_placements(pp):
    """ Filter out less specific placements early

        For the best chance of success, we want the most specific match with
        a set of instructions.

        Consider a input rule matching on IN_PORT, VLAN, ETH_DST, ETH_TYPE
        Then we could have all combinations of 0, 1, 2, 3 or 4 selected.
        This can result in 15 combinations, which then get multiplied out
        by all rules in future tables, so you quite quickly get 15 * 15 ...
        expansion.

        Consider:
        1) IN_PORT, VLAN, ETH_DST, ETH_TYPE -> Action A
        2) ETH_TYPE -> Action A

        1 is always preferable to 2, as it is less likely to interfere with
        other rules, but still applies the same action to the packet-space of
        interest.

        If only the default has empty actions, then it will still be selected
        as no higher priority rule has the same actions.

        pp: A list of placements, can be across multiple tables, filtering is
            applied per table
        return: A filtered list of placements
    """
    # Filter out less specific rules, this might result in more general rules
    # resulting in heaps of pointless rules. Which then get expanded even more
    # once combined with other tables.
    if len(pp) <= 1:
        return pp
    npp = []
    # Group matches, pick the most specific match with the same instructions
    for table, items in itertools.groupby(sorted(pp, key=lambda x: x.table),
                                          key=lambda x: x.table):
        # Filter to the most specific match per unique instruction.
        dinst = {}
        for p in items:
            inst = p.instructions.canonical()
            if inst in dinst:
                dinst[inst].append(p)
            else:
                dinst[inst] = [p]
        new_items = []
        for _inst, placements in viewitems(dinst):
            # Accept those with the longest match, there can be multiple
            # matches of same length, we accept all of these.
            # Note: by using canonical instructions there may be more than
            # one placement with the same match. We only take one.
            s = sorted(placements, key=lambda x: len(x.match))
            longest = len(s[-1].match)
            matches_inc = set()
            while s and len(s[-1].match) == longest:
                place = s.pop()
                if place.match not in matches_inc:
                    matches_inc.add(place.match)
                    new_items.append(place)

        # Disable the next check, as it is not currently implemented correctly
        npp += new_items

    return npp

def get_possible_paths_rec(to_place, orig_ingress, table, path, path_merge,
                           collect):
    """ Recursively computes possible full paths for a rule

    Note: the paths returned are filtered by filter_less_specific_placements
    to return the paths which include most of the original match.

    to_place: The Rule to find a path for
    orig_ingress: The match of the first rule in the path
    table: The TTPTable to try fit to_place into
    path: The path collected thus far
    path_merge: path flattened to a single rule to avoid recomputing.
    collect: Resulting list of tuples in the form (full-paths, flattened).
             Where a full path is a list/tuple of Rules ending in a rule
             without a goto.
             Flattened, is that path as a single Rule, i.e. all Rules in the
             path merged.
    """
    # Get all partial placements in this table

    possible = Remaining()
    for flow in table.flow_mod_types:
        res = flow._satisfies(to_place, final=False)
        possible.update(res)
        for rule in chain.from_iterable(viewvalues(res)):
            rule.loc = flow

    # Add built-in rules, use satisfies so that actions are eaten
    for built_in in table.built_in_flow_mods:
        expected = rule_from_ttp(built_in)
        res = built_in._satisfies(to_place, final=False)
        for unplaced, places in viewitems(res):
            for place in places:
                # XXX Some built-in rules incorrectly use optional meta-members
                # If so, there should be more than one placement.
                # Will also stop picking rules with unknown extension fields $FIELD
                if place != expected:
                    continue
                place.loc = built_in
                place.built_in = True
                possible[unplaced] = place

    # Filter less specific placements
    #
    # Convert to a list of placements, and then map back to
    # the placed unplaced set.
    for unplaced, placeds in possible.items():
        for placed in placeds:
            placed.unplaced = unplaced

    possible_raw = set().union(*possible.values())
    if len(possible_raw) <= 1:
        filtered_possible = possible
    else:
        filtered_places = filter_less_specific_placements(possible_raw)

        filtered_possible = Remaining()
        for place in filtered_places:
            filtered_possible[place.unplaced] = place

    for place in chain.from_iterable(viewvalues(possible)):
        del place.unplaced

    possible = filtered_possible

    for unplaced, placeds in viewitems(possible):
        for placed in placeds:
            next_path = path + (placed,)
            next_path_merge = path_merge + placed

            # End of pipeline?
            if placed.instructions.goto_table is None:
                if unplaced.instructions.full_actions().empty():
                    collect.append((next_path, next_path_merge))
                continue

            assert placed.instructions.goto_table >= table.number
            next_table = table.ttp.find_table(placed.instructions.goto_table)

            # Track the modified fields and include these in the match, that
            # that way the resulting path is specific as possible and is less
            # likely to conflict with other paths.
            next_match = next_path_merge.get_goto_egress(ingress=orig_ingress)

            next_to_place = Rule(priority=to_place.priority,
                                 table=to_place.table,
                                 cookie=to_place.cookie,
                                 match=next_match,
                                 instructions=unplaced.instructions)

            # Recurse, try and fit the remaining portion of the original rule
            get_possible_paths_rec(next_to_place, orig_ingress, next_table,
                                   next_path, next_path_merge, collect)

def get_possible_paths(to_place, ttp, ruleset_bdd, no_generalisation):
    """ Find all valid-looking full paths for a rule

        The paths returned are filtered to remove unlikely combinations.
        But, are not fully equivalence checked, and might have the wrong
        combined forwarding.

        Note: Generalised results are only returned if an exact fit is not
              found. See valid_generalisation() for more about generalisation.

        to_place: The rule to place, typically a rule compressed to a single
                  table.
        ttp: The Table Type Pattern to fit to_place into
        ruleset_bdd: The canonical input ruleset as a BDD. For generalisation
        no_generalisation: If True, don't attempt generalisation
        return: A list of paths as tuples
    """
    collect = []
    table = ttp.find_table(0)
    get_possible_paths_rec(to_place, to_place.match, table, tuple(),
                           Rule(priority=0, table=0), collect)

    correct_forwarding = []
    gen_forwarding = []
    to_place_norm = normalise([to_place])
    for path, merged_path in collect:
        normalised = normalise([merged_path])
        if normalised == to_place_norm:
            correct_forwarding.append(path)
        else:
            if (not no_generalisation and
                    valid_generalisation(normalised, to_place_norm, ruleset_bdd)):
                gen_forwarding.append(path)

    if correct_forwarding:
        return correct_forwarding
    return gen_forwarding

def get_partial_placement(frw, ttp):
    """ Rules a list of partial placements for a rule

        This will return full placements also and returns placements
        which comprise of default rules.

        frw: The Rule
        ttp: The TableTypePattern to place into
    """
    options = []
    for table in ttp.get_tables():
        for flow in table.flow_mod_types:
            # Try a partial placement
            res = flow._satisfies(frw, final=False)
            if res:
                for x in chain.from_iterable(viewvalues(res)):
                    x.loc = flow
                    options.append(x)

    # Add default rules
    for f in ttp.collect_children(TTPFlow):
        # Exclude egress tables
        if f.built_in and f.parent.number <= 60:
            res = rule_from_ttp(f)
            res.built_in = True
            if frw.match.issubset(res.match):
                options.append(res)

    return options
    # Now what's left into another table, and so on ...


def walk_through(pp):
    """ Return all valid and terminating full paths of the partial placements

        This method does not include incomplete paths, every path must start
        from table 0 and follow through gotos and terminate at a rule without
        a goto.

        TODO: Consider allowing a goto on the final rule, probably not worth it
        while you could hit the table default it seems unlikely.

        pp: A list of partial placements
        return: An iterator returning subsets of the partial placements as
                tuples. Each starts at table 0 following goto's and ends
                at a rule without a goto.

    """
    table_dict = defaultdict(list)
    for p in pp:
        table_dict[p.table].append(p)
    stack = [iter(table_dict[0])]
    ret = ['FAKE']
    while stack:
        try:
            ret.pop()
            p = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        ret.append(p)
        if p.instructions.goto_table is None:
            yield tuple(ret)
        else:
            stack.append(iter(table_dict[p.instructions.goto_table]))
            ret.append('FAKE')


def walk_through_incomplete(pp):
    """ Return all paths including incomplete of the partial placements

        Returns all combinations of rules, following table gotos like in
        walk_through, however will also return incomplete combinations, with
        tables skipped. The reason is to allow lower priority versions of a
        similar rule to be used.

        NOTE: Alternate versions are better handled via generalisation. Using
        this version results in way too many results to check.

        pp: A list of partial placements
        return: An iterator returning subsets of the partial placements as
                tuples.
    """
    table_dict = defaultdict(list)
    for p in pp:
        table_dict[p.table].append(p)

    # Stack of generators
    stack = [iter(table_dict[0])]
    # Ensure we always have a item on the list, so we can pop it
    ret = ["FAKE"]
    while stack:
        try:
            ret.pop()
            p = stack[-1].next()
        except StopIteration:
            stack.pop()
            continue
        # Goes to
        ret.append(p)
        if len(ret) > 1:
            # Return answers with elided placements, however ensure
            # that the final placement is included and the path through the
            # pipeline is valid.
            # Thus allowing a lower priority equivalence to be used.
            for i in all_combinations(ret[0:-1]):
                yield i + (ret[-1],)
        else:
            yield tuple(ret)
        if p.instructions.goto_table is not None:
            stack.append(iter(table_dict[p.instructions.goto_table]))
            ret.append("FAKE")


def memoize_reg(function):
    """ Result cache for Generalisation

    Note: This assumes norm does not change!!
    """
    memo = {}

    def wrapper(*args):
        if args[0] in memo:
            return memo[args[0]]
        rv = function(*args)
        memo[args[0]] = rv
        return rv
    return wrapper

def valid_generalisation(new_norm, input_norm, ruleset_norm):
    """ Check if it is useful to generalise the match on this rule

        If we do not include all matches of the original rule in the new
        rule, then the new rule will match more packets than the old. If
        that extra packet-space matched has the same forwarding then this
        is useful and could reduce the ruleset. Otherwise, it is not
        worth exploring.

        This checks both actions and match.

        new_norm: The new, more general, rule normalised
        input_norm: The input rule normalised
        norm: The input ruleset normalised
        return: True, if the generalisations is applicable to
                the extra packet space.

        For example consider:
               Table 1                    Table 2
        IP1 -> Set(Out:1) Goto:2   TCP:80 -> [clear_actions]
        * -> Goto:2                * -> []

        When compressed to a single table
        IP1, TCP:80 -> []
        IP1         -> [Out:1]
        TCP:80      -> []
        *           -> []

        When installing in a reversed order pipeline:
           Table 1         Table 2
        TCP:80 -> []   IP1 -> [Out:1]
        * -> Goto:2    *   -> []

        The rule IP1, TCP:80 won't be installed because IP1 is not matched.

        Instead we collect the partial paths and compare against the action
        of all.
    """
    # Forwarding must be the same for the input rule's packet-space
    if new_norm.intersection(input_norm) != input_norm:
        return False

    # Either: 1) Require all newly matched packets have the same forwarding
    # in for the ruleset as a whole.
    #if new_norm.intersection(ruleset_norm) != new_norm:
    #    return False

    # Or 2) Check that at least some of newly matched packets have this same
    # forwarding.
    if new_norm.intersection(ruleset_norm) != input_norm.intersection(ruleset_norm):
        return True
    return False

def get_possible_split_placements(frw, ttp, ruleset_norm, no_generalisation):
    """ Find possible paths through the target pipeline

    Paths will have the same forwarding as the original rule for the
    packet-space matched by the original rule. With generalisation a
    path might apply this forwarding to more of the packet-space.

    frw: The flow to place
    ttp: The table type pattern, to fit into.
    ruleset_norm: The normalised input ruleset
    no_generalisation: Don't try generalisation, generalisation is only used
                       when no exact placements can be made
    return: A list of valid split placements, each split is a list of flows
            to install
    """
    pp = get_possible_paths(frw, ttp, ruleset_norm, no_generalisation)
    return pp


def get_possible_rule_placements(frw, ttp, link_loc=False):
    """
    frw: The working flow rule
    link_loc: Link the TTP location to the rule
    return a list of possible locations that rule could be installed
    """

    # Zero out the goto, when we rewrite we might keep or skip this!!
    old_goto = frw.instructions.goto_table
    frw.instructions.goto_table = None

    res = []

    # Make into real placements
    flow_types = [table.flow_mod_types for table in ttp.get_tables()]
    for flow in chain(*flow_types):
        placements = flow._satisfies(frw)
        for place in chain.from_iterable(viewvalues(placements)):
            if link_loc:
                place.loc = flow
            res.append(place)

    # Add built-in rules
    built_ins = [table.built_in_flow_mods for table in ttp.get_tables()]
    for built_in in chain(*built_ins):
        expected = rule_from_ttp(built_in)
        placements = built_in._satisfies(frw)
        for rule in chain.from_iterable(viewvalues(placements)):
            # XXX Some built-in rules incorrectly use optional meta-members
            # If so, there should be more than one placement.
            # Will also stop picking rules with unknown extension fields $FIELD
            if rule != expected:
                continue
            rule.loc = built_in
            rule.built_in = True
            res.append(rule)

    frw.instructions.goto_table = old_goto

    # The exact same placement can be supported by multiple flow entries
    # in the TTP. As these rule is identical only return one of each.
    # NOTE: The placement selected is random
    return list(set(res))


def get_highest_priority_reachable(Sr):
    """
    Sr: The remaining unconsidered part of the original solution
    Return: the highest priority rule which is also reachable,
            i.e. that is to say it is in table 1. Or None if no
            rules are reachable.
    """
    reachable = [r for r in Sr if r.table == 0]
    # Sort decreasing so we get the highest priority
    reachable.sort(key=lambda x: -x.priority)
    if reachable:
        return reachable[0]
    return None


def generate_consideration_order(Sr):
    """ The order the solver attempts to fit rules """
    return sort_ruleset(Sr)


def get_best_solution(Pw):
    """ Returns the best solution.
        Currently this is the smallest """
    smallest = None
    for x in Pw:
        if smallest is None or len(x) < len(smallest):
            smallest = x
    return smallest


def find_single_table(flows, deps):
    """
    Highlights rules where single table will be helpful

    We are looking for cases that two rules can fit in the same table
    but not at the same time.

    TODO: Also consider requiring a larger match in a table!!! But most of
    the time matches are exact or all.
    """

    #: The only option is to merge these rules i.e. individual placement only
    #: includes the table that requires a merge
    needs_merge = []
    can_merge = []  # Can be merged, but might be OK without

    for flow in flows:
        for child in flow.children:
            if flow.table != child.table:
                # Do we have placements in the same table?
                f_tables = set([p.table for p in flow.placements])
                c_tables = set([p.table for p in child.placements])
                overlap = f_tables.intersection(c_tables)
                if overlap:
                    # Cool we have some placements
                    # We know a dep exists between tables iff a rule directs
                    # traffic to another, so there is some overlap!
                    # This means putting them in the same table is not an
                    # option unless the overlap is complete. Such as goto
                    # the next table, in which case merging into one still
                    # makes sense!!
                    if len(f_tables) == 1 and len(c_tables) == 1:
                        # The only option
                        needs_merge.append((flow, child))
                    else:
                        can_merge.append((flow, child))

    return needs_merge, can_merge


class BadOverlap(Exception):
    """ Two rules have been installed into a solution which overlap each
        other, but have different behaviour.
    """
    def __init__(self, existing, addition):
        super(BadOverlap, self).__init__(
            "Bad overlap between: " + str(existing) +
            " and " + str(addition))
        self.existing = existing
        self.addition = addition


class Solution(object):
    """ Represents a solution. Keeps a mapping of original rules to installed
        rules and other fast lookup structures.
    """

    def __init__(self):
        #: Mapping a rule to its list of merged equivalences
        self.merged_left = {}
        #: Duplicate detection Map (match, table) -> rule. Then figure out if
        #: we are copying it or not Keep the higher priority rule
        self._placements = {}
        self._cache_single_table = None

    def _add(self, r, tags=None, overwrite=False):
        """ Add a single flow to the solution.
            This checks for duplicate rules within the same table and
            keeps the highest priority.
            r: The flow rule
            tags: A dictionary of lists of information about that rule,
                  if a rule at the same priority is merged so are these dicts
            overwrite: If False an overlap with different actions raises a
                       BadOverlap exception.
                       If True this rule will overwrite any existing.
            return: Returns the rule added or the equivalent already installed.
                    Otherwise if the rule is not reachable returns None.
        """
        placements = self._placements
        key = (r.match.get_wildcard(), r.table)
        if tags is None:
            tags = {}

        if key in placements:
            # If it already exists check priority and keep the highest
            existing = placements[key]
            if r.priority > existing.priority:
                r.tags = tags
                # Replace it
                # First check for overlap
                same_priority = [x for x in viewvalues(placements) if
                                 x.priority == r.priority and
                                 x.table == r.table]
                for x in same_priority:
                    if wildcard_intersect(x.match.get_wildcard(),
                                          r.match.get_wildcard()):
                        if x.instructions != r.instructions:
                            raise BadOverlap(x, r)
                placements[key] = r
                self._cache_single_table = None
                return r
            elif r.priority == existing.priority:
                # If both have the same actions merge
                # Equal priority, check the rules are the same
                if existing != r:
                    # In general this is the case that we try and install
                    # a clear_actions, write or apply version of the same rule
                    # in the same place. Only one can actually be hit,
                    # so lets just ensure these conflicts are never installed.
                    if overwrite:
                        # The search solver still relies on the old behaviour
                        placements[key] = r
                        self._cache_single_table = None
                        r.tags = self.merge_tags(existing.tags, tags)
                        return r
                    else:
                        # The SAT solvers will ensure this combination does not
                        # happen again, which cuts down the search space.
                        r.tags = tags
                        raise BadOverlap(existing, r)

                # Merge the tags
                existing.tags = self.merge_tags(existing.tags, tags)
                return existing
            else:  # Rule not reachable, lower priority
                return None
        else:
            same_priority = [x for x in viewvalues(placements) if
                             x.priority == r.priority and
                             x.table == r.table]
            r.tags = tags
            # Check for overlap
            for x in same_priority:
                if wildcard_intersect(x.match.get_wildcard(),
                                      r.match.get_wildcard()):
                    if x.instructions != r.instructions:
                        if 'built_in' in x.tags and 'built_in' in r.tags:
                            print("Warning: Built-in flow rules have a bad overlap.")
                        else:
                            raise BadOverlap(x, r)

            placements[key] = r
            self._cache_single_table = None
            return r

    def add_hidden(self, rule, orig, tags=None):
        """ Add a hidden rule, used for merging but that is not actually
            installed
        """
        if tags is None:
            tags = {}
        rule.tags = tags
        self.merged_left[id(orig)] = [rule]

    def add(self, rules, orig, tags=None, overwrite=False):
        if not rules:
            return
        res = None
        for r in rules:
            res = self._add(r, tags, overwrite)
        if res is not None:
            self.merged_left[id(orig)] = [res]
        else:
            # Something else is already in this place, that is OK
            # Keep the mapping so we know how to map rules
            self.add_hidden(r, orig, tags)

    def copy_and_add(self, rules, orig, tags=None, overwrite=False):
        s = Solution()
        s.merged_left = {}
        for a, b in viewitems(self.merged_left):
            s.merged_left[a] = list(b)
        s._placements = dict(self._placements)
        s.add(rules, orig, tags, overwrite)
        # s._placements = self._placements + tuple(rules)
        # if len(rules):
        #     s.merged_left[id(orig)] = [s._placements[-1]]

        return s

    def get_ordered_rules(self):
        return sort_ruleset(viewvalues(self._placements))

    def __str__(self):
        ret = []
        for x in self.get_ordered_rules():
            ret.append(str(x))
        return '\n'.join(ret)

    def __repr__(self):
        return repr([x for x in viewitems(self._placements)])

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

    def __hash__(self):
        return hash(tuple(viewitems(self._placements)))

    def __eq__(self, other):
        # Tuples check objects before length!!! Why!!
        if len(self._placements) == len(other._placements):
            return self._placements == other._placements
        return False

    def __len__(self):
        return len(self._placements)

    def add_merged(self, flow, merge, tags=None):
        """ Add this rule merged with another

            tags: A map of list of additional storage
        """
        merged = []
        if tags is None:
            tags = {}
        for placed in self.merged_left[id(merge)]:
            try:
                # If a rule has already been merged we might try a merge which
                # results in an empty match set. This is OK.
                res = placed.merge(flow)
                assert hasattr(flow, "children")
                ntags = self.merge_tags(placed.tags, tags)
                res.priority += flow.priority
                res.instructions.goto_table = placed.instructions.goto_table
                r = self._add(res, ntags)
                if r is not None:
                    merged.append(r)
            except Exception:
                traceback.print_exc()
                raise
        if id(flow) in self.merged_left:
            self.merged_left[id(flow)] += merged
        else:
            self.merged_left[id(flow)] = merged

    @staticmethod
    def merge_tags(a, b):
        """ Returns new tags resulting from merging two tag dicts """
        ntags = {}
        for k, v in viewitems(a):
            ntags[k] = list(v)
        for k, v in viewitems(b):
            if k in ntags:
                ntags[k] += v
            else:
                ntags[k] = v
        return ntags


class SolverStats(object):
    """ Performance counters

                            Counters:
        iterations: The number of iterations required
        solutions_checked: The number of solutions compared
        bad_overlaps: The number of solutions thrown due to conflicting
                      overlaps
        sat_variables: The number of SAT variables
        sat_clauses: The initial number of SAT clauses
        sat_solution_variables: The number of solution variables
        sat_placement_excluded: The number of placements excluded
        sat_clauses_added: The number of extra clauses added
        input_ruleset_size: No. flow rules originally read from file
        ruleset_hook_size: No. flow rules after executing all ruleset hooks
        pre_solve_size: No. flow rules after executing all pre_solve
                        such as (compression etc.)
        post_solve_size: No. of flows from solver, before post_solve (redup)
        solution_size: No. flows in the final solution
        valid_solutions: The number of valid solutions found
        unique_solutions: The number of unique valid solutions found
        reactioning: The number of rules added by re-actioning
        problem_space: A list of the number of transformations per rule
    """

    def __init__(self):
        self.iterations = 0
        self.solutions_checked = 0
        self.bad_overlaps = 0
        self.sat_variables = 0
        self.sat_clauses = 0
        self.sat_solution_variables = 0
        self.sat_placement_excluded = 0
        self.sat_clauses_added = 0
        self.input_ruleset_size = 0
        self.ruleset_hook_size = 0
        self.pre_solve_size = 0
        self.post_solve_size = 0
        self.solution_size = 0
        self.valid_solutions = 0
        self.unique_solutions = 0
        self.reactioning = 0
        self.problem_space = []

    def __str__(self):
        """ Returns a summary of the counters """
        sret = []
        ret = []

        def perc(a, b):
            """ Return a as a percentage of b, as a nice string """
            if b:
                return "{:.1f}%".format(100*float(a)/float(b))
            else:
                return ""

        ret = []
        if self.input_ruleset_size:
            ret.append("Original ruleset size: " +
                       str(self.input_ruleset_size))
        if self.ruleset_hook_size:
            ret.append("\t After ruleset_hook: " +
                       str(self.ruleset_hook_size) + " " +
                       perc(self.ruleset_hook_size, self.input_ruleset_size))
        if self.pre_solve_size:
            ret.append("\t After pre_solve (compression etc.): " +
                       str(self.pre_solve_size) + " " +
                       perc(self.pre_solve_size, self.input_ruleset_size))
        if self.post_solve_size:
            ret.append("\t Post solve size: " +
                       str(self.post_solve_size))
        if self.solution_size:
            ret.append("\t Solution ruleset size: " +
                       str(self.solution_size) + " " +
                       perc(self.solution_size, self.input_ruleset_size))
        if self.iterations:
            ret.append("Iterations: " + str(self.iterations))
        if self.bad_overlaps:
            ret.append("Bad Overlaps: " + str(self.bad_overlaps))
        if self.solutions_checked:
            ret.append("Solutions Checked: " + str(self.solutions_checked))
        ret.append("Valid Solutions: " + str(self.valid_solutions))
        ret.append("Unique Solutions: " + str(self.unique_solutions))
        if self.reactioning:
            ret.append("Re-actioning Splits Added: " + str(self.reactioning))
        if self.sat_variables:
            ret.append("SAT Variables: " + str(self.sat_variables))
        if self.sat_solution_variables:
            ret.append("SAT Sln Variables: " +
                       str(self.sat_solution_variables))
        if self.sat_clauses:
            ret.append("SAT Clauses: " + str(self.sat_clauses))
        if self.sat_clauses_added:
            ret.append("SAT Clauses added: " + str(self.sat_clauses_added))
        if self.sat_placement_excluded:
            ret.append("SAT Placements excluded: " +
                       str(self.sat_placement_excluded))
        if self.problem_space:
            ret.append("SAT Search Space List: " + ", ".join(map(str, self.problem_space)))
            ret.append("SAT Search Space: " + str(reduce(operator.mul, self.problem_space)))
        if ret:
            sret.append("--- Counters ---")
            sret += ret
        return "\n".join(sret)


class Solver(object):
    ttp_file = None  # The TTP file path
    ttp = None  # The loaded TTP structure
    single = False  # Use at most 1 thread
    dummy = False  # Use dummy threading
    stats = None  # The raw ryu input
    Si = None  # The initial solution
    deps = None  # The dependencies in the original problem (Si)
    consider_order = None  # The order to consider rules in
    ThreadPool = None  # The thread pool to use
    counters = None  # Performance counters
    timers = None  # Performance timers
    p_bar = None  # A tqdm progress bar or noop if not reporting progress

    def __init__(self, ttp_file, timers=None, single=False, dummy=False,
                 print_failure=False, progress=False, log_level='INFO',
                 ttp_log_level='INFO', no_compression=False, no_merge=False,
                 no_reactioning=False, no_generalisation=False, options=[], iterations=None):
        """ The generic base class of a solver.
            ttp_file: The location of the TTP to be loaded
            timers: If provided a TimerHierarchy where a solver can store timing information
            single: Use at most one thread
            dummy: Use python threads instead of forking
            print_failure: Print output describing flows causing a failure
            progress: Disable tracking and printing progress and statistics
                      about solving the solution.
            log_level: The log level of the solver
            ttp_log_level: The log level to use when loading the ttp
            no_compression: Disable ruleset compression
            no_merge: Disable merging rules
            no_reactioning: Disable reactioning
            no_generalisation: Disable generalisation
            options: A list of additional options
            iterations: Limit the iterations of the Solver

            Once created solve(capture) will find a solution.
        """
        self.counters = SolverStats()
        if timers is None:
            self.timers = TimerHierarchy('Solver')
        else:
            self.timers = timers
        self.single = single
        self.dummy = dummy
        self.ttp_file = ttp_file
        self.print_failure = print_failure
        self.progress = progress
        self.no_compression = no_compression
        self.no_merge = no_merge
        self.no_reactioning = no_reactioning
        self.no_generalisation = no_generalisation
        self.options = options
        self.iterations = iterations
        if not isinstance(log_level, int):
            log_level = getattr(logging, log_level, logging.INFO)
        SOLVER_LOGGER.setLevel(log_level)
        if not isinstance(ttp_log_level, int):
            ttp_log_level = getattr(logging, ttp_log_level, logging.INFO)
        ttp_logger = logging.getLogger("TTP")
        ttp_logger.setLevel(ttp_log_level)

        if progress:
            self.p_bar = tqdm
        else:
            self.p_bar = lambda x, *_, **__: x

        # Load the TTP
        with self.timers("Loading TTP", timer_class=OneShotTimer):
            self.ttp = TableTypePattern(ttp_file, logger=ttp_logger)

            # I don't trust priorities in the TTP
            # Ignore priorities when placing rules
            for x in self.ttp.collect_children(TTPFlow):
                if not x.built_in:
                    x.priority = None

        if not single:
            if dummy:
                from multiprocessing.dummy import Pool
                self.ThreadPool = Pool
            else:
                from multiprocessing import Pool
                self.ThreadPool = Pool

    @time_func("Compress Priorities")
    def compress_placement_priorities(self, ruleset, can_merge):
        """ Compresses placements differing only by priority, when safe

        * Compresses otherwise identical placements with the different
          priorities into a single priority, as long as this does not
          reduce search-space.
          Therefore, only if there are no rules with priorities between
          that with an overlapping match. Thus merging these priorities
          does not remove a relative priority with relation to any
          other rules.
        * Additionally replaces all identical placements with the same
          instance.

          return: None, updates rule.placements and rule.split_placements
        """
        can_merge = None
        if can_merge is None:
            can_merge = {}

        places = set()
        places_ids = set()
        # Collect direct placements
        for rule in ruleset:
            for place in rule.placements:
                places.add(place)
                places_ids.add(id(place))
        # Collect split placements
        if hasattr(rule, "split_placements"):
            for rule in ruleset:
                for place in chain.from_iterable(rule.split_placements):
                    places.add(place)
                    places_ids.add(id(place))
        # Collect merge placements
        for place in chain.from_iterable(viewvalues(can_merge)):
            places.add(place)
            places_ids.add(id(place))

        # To simplify, we should remove rules where there is an identical version at
        # a different priority, and no rules in between with overlaps. I.e. when
        # picking a different priority version of the same rule will still have the
        # exact same deps with other rules.
        table = None
        tracking = {}
        to_replace = {}  # Replace first with second in all appearances

        for rule in sort_ruleset(places):
            rule_key = (rule.match, rule.instructions.canonical())
            if rule.table != table:
                # Reset we are starting a new table
                tracking = {rule_key: rule}
                # Replace all instances of the same instance
                to_replace[rule] = rule
                table = rule.table
                continue
            # Fast check if we are tracking another rule of the same match to
            # with
            if rule_key in tracking:
                to_replace[rule] = tracking[(rule.match, rule.instructions.canonical())]
                continue
            # Otherwise lets see if we have any bad overlap with another
            # rule and start tracking this rule
            to_remove = []
            for key, tracked in tracking.items():
                if tracked.match == rule.match:
                    # same match different instructions, not a real
                    # conflict as they will never be picked together
                    continue
                intersection = wildcard_intersect(tracked.match.get_wildcard(),
                                                  rule.match.get_wildcard())
                if intersection:
                    # intersection, but differing matches
                    to_remove.append(key)
            for remove in to_remove:
                del tracking[remove]
            # Replace all instances of the same instance
            to_replace[rule] = rule
            # Start tracking this rule
            tracking[rule_key] = rule

        # Replace placements
        for rule in ruleset:
            new = set()
            for place in rule.placements:
                new.add(to_replace[place])
            rule.placements[:] = list(new)
            if hasattr(rule, "split_placements"):
                new = set()
                for split in rule.split_placements:
                    new_split = []
                    for place in split:
                        new_split.append(to_replace[place])
                    new.add(tuple(new_split))
                rule.split_placements[:] = list(new)
        for placements in viewvalues(can_merge):
            new_placements = {to_replace[place] for place in placements}
            placements[:] = list(new_placements)

    @time_func("Re-actioning")
    def reactioning(self, ruleset, can_merge):
        """ Replaces the actions on flows rules with those with the same matches

        Only considers changes to split placements. But checks using the
        placements from all transformations.

        There is no return, the result is added directly to all rules

        Consider for example, being reinstalled back to the same pipeline:
           Table 1                       Table 2
        IP:1 -> Set(Out:1) goto 2    TCP:60 -> Clear
        * -> goto 2                  * -> []
        When flattened the combination of IP:1 and TCP:60 will have a higher
        priority than *. However, will contain no actions e.g.:
        IP:1, TCP:60 -> []
        IP:1         -> [Out:1]
        *            -> []

        The install of IP&TCP takes priority and does not install Out:1.
        So we cannot find a solution. Instead we notice that both only
        match IP:1 in table 1. And that Out:1 on IP&TCP does not change
        behaviour, as such it can be installed as such.

        This will change at most one rule along a path at a time
        See tables = [None]
        """
        if not ruleset or not hasattr(ruleset[-1], "split_placements"):
            return

        def candidate_key(rule):
            return (rule.table, rule.instructions.goto_table,
                    rule.match.get_wildcard())

        # Group into [candidate_key][equiv_instruct] -> set(places)
        match_dict = defaultdict(lambda: defaultdict(set))
        place2rule = {}
        for rule in self.consider_order:
            for place in rule.placements:
                match_dict[candidate_key(place)][place.instructions.canonical()].add(place)
                place2rule[place] = rule
            for place in chain.from_iterable(rule.split_placements):
                match_dict[candidate_key(place)][place.instructions.canonical()].add(place)
                place2rule[place] = rule

        # Gather all merge placements
        for place in chain.from_iterable(viewvalues(can_merge)):
            match_dict[candidate_key(place)][place.instructions.canonical()].add(place)
            place2rule[place] = rule

        # Generate re-actioned rules, with link to the original
        for place, rule in viewitems(place2rule):
            new_place = place.copy()
            new_place.reactioned = rule
            place2rule[place] = new_place

        #tables = sorted(set([x.table for x in place2rule]))
        tables = [None]
        for rule in self.p_bar(ruleset, "Re-actioning"):
            full_actions = rule.instructions.full_actions()
            for table in tables:  # Recurse tables, allows multiple changes
                                  # otherwise tables can be [None]
                to_add = set()
                for split in rule.split_placements:
                    for idx, place in enumerate(split):

                        # Can do for all tables, but this seems like a bad idea
                        if table is not None and place.table != table:
                            continue
                        # What can we change this split with?
                        # Only consider iff later has clear_actions??
                        new_placements = match_dict[candidate_key(place)]
                        for equiv_places in new_placements.values():
                            # All places in equiv_places will behave the same
                            new_place = next(iter(equiv_places))  # Get the first

                            # Now switch table x with this one, TODO REMOVE
                            # and check functionality, XXX put this as a key
                            if (new_place.instructions.goto_table !=
                                    place.instructions.goto_table):
                                continue

                            if len(equiv_places) == 1:  # only one skip early
                                if new_place == place:
                                    continue

                            # Generate the new split
                            candidate = split[0:idx] + (new_place,) + split[idx+1:]

                            if len(equiv_places) == 1:  # only one skip early
                                if candidate in rule.split_placements:
                                    continue

                            # NOW check equiv
                            # This should be the same as the original
                            new = reduce(operator.add, candidate)
                            if full_actions.equiv_equal(
                                        new.instructions.full_actions()):
                                for new_place in equiv_places:
                                    # We can change it, add it to a new split
                                    candidate = (split[0:idx] +
                                                 (place2rule[new_place],) +
                                                 split[idx+1:])
                                    if candidate not in rule.split_placements:
                                        to_add.add(candidate)
                self.counters.reactioning += len(to_add)
                rule.split_placements += set(to_add)
        return

    @time_func("Compute Dependencies")
    def compute_dependencies(self, ruleset):
        """ Calculate a rulesets dependencies

            Adds rule.children and rule.parents and
            saves the result in self.deps
        """
        # Deps the dependency mapping between rules
        # Only the direct deps
        self.deps = build_ruleset_deps(ruleset)
        # Tag each with children etc.
        node_to_tree(self.deps, ruleset)

    @time_func("Direct Placements")
    def compute_direct_placements(self, ruleset):
        """ Calculate direct transformations for all rules
            and store the result as a list against each rule.placements

            ruleset: The ruleset
            normalised: The ruleset normalised as a BDD
        """
        for flow in self.p_bar(ruleset, desc='Direct Placements'):
            flow.placements = get_possible_rule_placements(
                                    flow, self.ttp, True)
            flow.possible_locations = flow.placements

    def all_rule_combinations(self, rs, min_len=2):
        """ A generator returning all rule combinations of valid paths.

            A valid path begins at table 0, and follows gotos until completion.
            We generate all combinations including partial paths that don't
            start at table 0, or skip over part of the path.

            This method may return duplicates.
            Each combination returned will be ordered increasing by flow table.

            rs: The ruleset
            min_len: The minimum length of a combination to generate
        """
        def _rc(f_in):
            f = f_in[0]
            stack = [(c for c in f.children if c.table > f.table)]
            while stack:
                try:
                    c = next(stack[-1])
                except StopIteration:
                    stack.pop()
                    f_in = f_in[:-1]
                    continue
                for x in all_combinations(f_in, min_len-1):
                    yield x + (c,)
                f_in = f_in + (c,)
                stack.append((c for c in f_in[-1].children
                              if c.table > f_in[-1].table))

        table0 = (i for i in rs if i.table == 0)
        for f in table0:
            if min_len == 1:
                yield f
            for x in _rc((f,)):
                yield x

    @time_func("Merge Placements")
    def compute_merge_placements(self, ruleset):
        """ Calculate merge transformations for all rules

            Merge all rules in all combinations, limited to portions of full
            paths through the pipeline, following gotos.

            If self.no_merge is set this returns an empty dict

            return: A dictionary mapping a tuple of rules to their
                    merged placements
        """
        if self.no_merge:
            return {}

        # Hash on id to speed up the set operation, as flows have not been
        # copied they'll still have the same id
        # To keep this stable between runs we tag an id
        unique_hash = 0
        for rule in ruleset:
            rule.fake_hash = unique_hash
            unique_hash += 1
        old_hash = Rule.__hash__
        Rule.__hash__ = lambda s: rule.fake_hash
        combinations = set(self.all_rule_combinations(ruleset))
        Rule.__hash__ = old_hash
        for rule in ruleset:
            del rule.fake_hash

        can_merge = {}
        for c in self.p_bar(combinations, desc='Merge Placements'):
            try:
                priority = c[0].priority + c[1].priority
                merged = c[0].merge(c[1])
                for r in c[2:]:
                    priority += r.priority
                    merged = merged.merge(r)
                merged.priority = priority
                placements = get_possible_rule_placements(merged, self.ttp,
                                                          True)
                if len(placements) > 0:
                    can_merge[c] = placements
            except MergeException:
                # not mergable
                pass
        return can_merge


    @time_func("Split Placements")
    def compute_split_placements(self, ruleset, normalised):
        """ Calculate split transformations for all rules
            and store the result as a list against each rule.split_placements

            ruleset: The ruleset
            normalised: The ruleset normalised as a BDD
        """
        for flow in self.p_bar(ruleset, desc="Split Placements"):
            flow.split_placements = get_possible_split_placements(
                flow, self.ttp, normalised, self.no_generalisation)

    def ruleset_hook(self, ruleset):
        """ Allows modification of the input ruleset to an equivalent ruleset.

            NOTE: Only make changes that result in the same behaviour
            as the input set. Otherwise use pre_solve and post_solve hooks
            to make and reverse the change.

            This is run immediately once the input ruleset is loaded, and
            allows this to be modified.

            By default this returns the ruleset unmodified.
            ruleset: A priority ordered ruleset
            return: The modified ruleset, must remain priority ordered
        """
        # Load up priorities that work when merging tables
        scale_ruleset(ruleset)
        return ruleset

    def pre_solve(self, ruleset):
        """ Allows destructive modification of an input ruleset.

            E.g. simplification operations can be implemented here.
            It is up to the solver to save the input set if required as these
            can be chained.

            ruleset: A priority ordered ruleset
            return: An optionally modified priority ordered ruleset
        """
        return ruleset

    def post_solve(self, result):
        """ Allows a simplification made with pre_solve to be generalised back
            to a full solution.

            This function should check its result for equivalence with the
            input to pre_solve.
            If this fails return None, otherwise the new ruleset.

            When failure occurs it is expected that post_solve records the
            issue as pre_solve will be recalled with the same problem, as to
            avoid it next time.
            If not possible simply return the unmodified ruleset for pre_solve.

            result: The result from the solver (for the pre_solve set)
            return A full solution
        """
        return result

    def solve(self, capture_file, all_solutions=False):
        """ Loads the capture file and does initial analysis on the solution
            capture_file: A pickled input of ryu flow rules
            all_solutions: If set return a list rather than just the one TODO
            return: A solution or None if not found
        """

        with self.timers("Loading Ruleset", timer_class=OneShotTimer):
            # Load ruleset
            try:
                self.stats = ruleset_from_ryu(capture_file)
            except (ValueError, UnpicklingError):
                self.stats = ruleset_from_fib(capture_file)

            # Remove all cookies as these do not matter and result in duplicate
            # placements (only differing by cookie) which is expensive.
            for rule in self.stats:
                rule.cookie = None

            # Ensure all tables have a table-miss rule, if not add a drop
            match_all = Match()
            tables = {rule.table for rule in self.stats}
            for table in tables:
                default = [rule for rule in self.stats
                           if rule.table == table and rule.match == match_all]
                if not default:
                    self.stats.append(Rule(priority=0, table=table))
            # Sort the ruleset
            self.stats = sort_ruleset(self.stats)
            # Save ruleset stats
            self.counters.input_ruleset_size = len(self.stats)
            Si_hook = self.ruleset_hook(self.stats)
            self.counters.ruleset_hook_size = len(Si_hook)

        while True:
            with self.timers("Pre Solve"):
                Si = self.pre_solve(Si_hook)
                self.counters.pre_solve_size = len(Si)
                # Ensure the input is in the correct priority order
                assert sorted(Si, key=lambda f: (f.table, -f.priority)) == Si

            with self.timers("Solver Init"):
                self.solver_init()
                # Calculate the normalised result
                if {r.table for r in Si if r.table != 0}:
                    # Has more than one table
                    Si_single_table = to_single_table_scaled(Si)
                else:
                    Si_single_table = []
                    for rule in Si:
                        # Make a copy of the rules
                        Si_single_table.append(rule.copy())
                        Si_single_table[-1].path = (rule,)
                Si_normalised = normalise(Si_single_table)

            with self.timers("Run Solver"):
                res = self.run_solver(Si, all_solutions, Si_single_table, Si_normalised)

            with self.timers("Post Solve"):
                if res is None:
                    return None
                if all_solutions:
                    post_solve = []
                    for sln in res:
                        self.counters.post_solve_size = len(sln)
                        tmp = self.post_solve(sln)
                        self.counters.solution_size = len(tmp)
                        if tmp is not None:
                            post_solve.append(tmp)
                    return post_solve
                self.counters.post_solve_size = len(res)
                res = self.post_solve(res)
                self.counters.solution_size = len(res)
                if res:
                    return res

    def solver_init(self):
        """ Called prior to run_solver
            Gives the solver a chance to zero its state.
        """
        self.deps = None
        self.consider_order = None
        return None

    def run_solver(self, Si, all_solutions, Si_single_table, Si_normalised):
        consider_order = generate_consideration_order(Si)
        self.consider_order = consider_order
        self.compute_dependencies(Si)
        # Inherit this, this solves nothing
        return None


def check_solution(new, target, diff=False):
    """ Given a solution check if it is eqiv to another
        new: The new Solution
        target: A pre-compiled normalised target solution
        Return: True or False
    """
    single_merged_sln = new.to_single_table()
    nsingle_merged_sln = normalise(single_merged_sln)
    return check_equal(nsingle_merged_sln, target, diff=diff)


def isolate_rule(placement, flow):
    """ Given a placement and rule, isolate the function of the rule
        placement: A Rule representing a merged placement
        flow: The Rule to isolate
    """
    dup = placement.copy()
    dup.match = flow.match.copy()
    rem_apply = []
    for action in dup.instructions.apply_actions:
        if (action in flow.instructions.apply_actions or
                action in flow.instructions.write_actions):
            continue
        else:
            rem_apply.append(action)
    rem_write = []
    for action in dup.instructions.write_actions:
        if (action in flow.instructions.apply_actions or
                action in flow.instructions.write_actions):
            continue
        else:
            rem_write.append(action)

    for r in rem_write:
        dup.instructions.write_actions.remove(r)
    for r in rem_apply:
        dup.instructions.apply_actions.remove(r)
    dup.priority = flow.priority
    return dup
