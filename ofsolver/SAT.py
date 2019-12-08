#!/usr/bin/python
""" The SAT based rule-fitting solver implementations.

    There are three solver variations:

    SATSolver:
    The basic solver which only considers directly placing and merging
    input rules to find placements in the target pipeline.

    SplitSATSolver:
    A variation of the basic solver which also splits input rules
    into multiple tables to find placements in the target pipeline.

    SingleSATSolver:
    A variation of SplitSATSolver which first converts the input
    ruleset to a single-table.

    SingleSATSolver is the recommended solver
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

from collections import defaultdict, namedtuple, Counter
import os
import subprocess
import itertools
import functools
import tempfile

from bidict import bidict
from six import viewitems, viewvalues
import zmq

from ofequivalence.normalisebdd import (normalise, check_equal,
                                        find_conflicting_paths, BDD, wc_to_BDD)
from ofequivalence.headerspace import (get_wildcard_mask)
from ofequivalence.ruleset import (compress_ruleset)

# util.boolexpr is slower
from .util.satispy import (Variable, Minisat, reduce_or, reduce_and,
                           reduce_onehot, to_dimacs, variable_name,
                           reduce_AMO)

from .solver import (Solver, SOLVER_LOGGER, Solution, Rule, simulate_actions,
                     simulated_equals, BadOverlap, to_single_table_scaled,
                     check_solution, TTPFlow, rule_from_ttp,
                     wildcard_intersect)


__location__ = os.path.realpath(
        os.path.join(os.getcwd(), os.path.dirname(__file__)))

def jump_check_sln(sat, nsingle_Si, sln):
    return sat.check_sol(sln, nsingle_Si)

"""
SAT Variable naming, each variable is a letter code followed by a
number, these numbers are unique regardless of letters.

Transformations:
s -> Split transformation
     One original rule maps to multiple placements
d -> Direct placement transformation
     One original rule maps to a single placement
m -> Merge transformation
     Multi original rules map to a single placement
b -> A rule built-in to the target pipeline

Placements:
p -> A placed rule (all transformations map to one or more placements)
h -> A hit placement
g -> A rule goes to this table
fm -> A fully merged rule

Helpers:
mt -> A Merge Table mapping
      (Each merge transformation results in a placement in a given table)
x -> An xor extra variable, used to simply the expression
"""
# Pickle needs to be able to find these
TransDirect = namedtuple("TransDirect", ["flow", "place"])
TransMerge = namedtuple("TransMerge", ["flows", "place"])
TransSplit = namedtuple("TransSplit", ["flow", "split"])
MapMergeTable = namedtuple("MapMergeTable", ["flow", "table"])


class FakeSln(dict):
    pass

class SATSolver(Solver):
    """ A class to solve the placement problem using a SAT solver.
    """
    assign_id = None  # Counting ID for mapping deps
    v_direct = None  # Direct transformation variables (flow, place) -> V
    f2v_direct = None  # A mapping of flow to variables
    v_merge = None  # Rules merged (parent, child, table) -> V
    f2vpc_merge = None  # Map (parent, child) to variables
    f2vp_merge = None  # Map parent to variables
    f2vc_merge = None  # Map child to variables
    v_rule_merge_table = None  # Rules merged (flow, table) -> V
    rems = None  # Items to remove next time around
    v_built_in = None  # built-in -> V
    v_placement = None  # placement (rule) -> V
    v2placements = None  # V (merge, direct, split, built-in) -> placement V
    v_hit = None  # placement (var) -> V
    v_goto_table = None  # table (int) -> V
    v_fully_merged = None  # original flow -> V


    def __init__(self, *args, **kwargs):
        super(SATSolver, self).__init__(*args, **kwargs)
        if not self.single:
            SOLVER_LOGGER.warning("The SAT solver does not fully support"
                                  " multi-threaded solving. Switching to"
                                  " single-threaded mode.")
            self.single = True

    def register_goto_table(self, table_id):
        """ Register a variable that represents packets reach this table.

            This variable is used to ensure a default table-miss rule is
            installed in every table that sees packets.

            table_id: The table id as an integer
            return: The corresponding SAT Variable
                    If already registered this returns the existing Variable.
        """
        if table_id in self.v_goto_table:
            return self.v_goto_table[table_id]
        self.assign_id += 1
        table_var = Variable('g' + str(self.assign_id))
        self.v_goto_table[table_id] = table_var
        return table_var

    def register_hit(self, place_var):
        """ Register a Variable that represents packets reach this placement

            As only the highest priority rule is hit, all lower priority
            rules shadowed by a rule are no-ops. Thus we limit the solver to
            not return the same combination of 'hit' rules again; to prevent
            searching equivalent solutions with different combinations of
            shadowed rules.

            place_var: The placement Variable from register_placement
            return: The corresponding SAT Variable
                    If already registered this returns the existing Variable.
        """
        if place_var in self.v_hit:
            return self.v_hit[place_var]
        self.assign_id += 1
        hit_var = Variable('h' + str(self.assign_id))
        self.v_hit[place_var] = hit_var
        return hit_var

    def register_placement(self, transformation, placement):
        """ Maps a transformation to an actual placement.

        Maintains the v_placement and v2placements mappings.

        If already registered this returns the existing Variable

        transformation: The Variable representing the transformation
        placement: The placement in the target pipeline, i.e. the Rule
        return: The variable for that placement, note it is one variable per
                placement. The mapping from transformation placement is stored
                in v2placements.
        """
        if placement not in self.v_placement:
            self.assign_id += 1
            v_place = Variable("p" + str(self.assign_id))
            self.v_placement[placement] = v_place
        else:
            v_place = self.v_placement[placement]
        self.v2placements[transformation].append(v_place)
        return v_place

    def register_fully_merged(self, rule):
        """ Register a variable that represents this flow is fully merged.

            This variable as part of checking that every rule has at least
            one transformation selected.

            rule: The rule in the original input
            return: The corresponding SAT Variable
                    If already registered this returns the existing Variable.
        """
        if rule in self.v_fully_merged:
            return self.v_fully_merged[rule]
        self.assign_id += 1
        fm_var = Variable('fm' + str(self.assign_id))
        self.v_fully_merged[rule] = fm_var
        return fm_var

    def map_direct(self, rule, placement):
        """ Maps a direct transformation to a variable in the solver

        If already registered this returns the existing Variable

        rule: The original rule
        placement: The direct placement
        return: The variable representing this transformation in the solver
        """
        direct = TransDirect(rule, placement)
        if direct in self.v_direct:
            return self.v_direct[direct]
        self.assign_id += 1
        direct_var = Variable("d" + str(self.assign_id))
        self.v_direct[direct] = direct_var
        self.f2v_direct[rule].append(direct_var)
        self.register_placement(direct_var, placement)
        return direct_var

    def map_merged(self, rules, place):
        """ Maps a merged transformation to a variable in the solver

        rules: The original merged rules. Must be ordered by table.
        place: The merged placement
        return: The variable representing this transformation in the solver
        """
        merge = TransMerge(rules, place)
        if merge in self.v_merge:
            return self.v_merge[merge]
        self.assign_id += 1
        merge_var = Variable("m" + str(self.assign_id))
        self.v_merge[merge] = merge_var
        self.register_placement(merge_var, place)
        for parent, child in zip(rules[:-1], rules[1:]):
            self.f2vp_merge[parent].append(merge_var)
            self.f2vc_merge[child].append(merge_var)
            self.f2vpc_merge[parent, child].append(merge_var)
        return merge_var

    def map_built_in(self, built_in):
        """ Maps a built-in rule into the SAT problem
            built_in: The built-in rule
            return: The variable representing this transformation in the solver
        """
        if built_in in self.v_built_in:
            return self.v_built_in[built_in]
        self.assign_id += 1
        built_in_var = Variable('b' + str(self.assign_id))
        self.v_built_in[built_in] = built_in_var
        self.register_placement(built_in_var, built_in)
        return built_in_var

    def map_merge_table(self, rule, table):
        """ Maps a merged or direct transformation to a table variable in the
            solver

        rule: The original merged rule
        table: The table of the placement
        return: The variable representing this constraint in the solver
        """
        mtable = MapMergeTable(rule, table)
        if mtable in self.v_rule_merge_table:
            return self.v_rule_merge_table[mtable]
        self.assign_id += 1
        mtable_var = Variable("mt" + str(self.assign_id))
        self.v_rule_merge_table[mtable] = mtable_var
        return mtable_var

    def SAT_link_fully_merged(self):
        """ Creates fully merged variables for the original ruleset

            A rule is fully merged if merged with all rule preceding or
            following in the pipeline (or both).

            The corresponding variable will be set, accessible via
            self.v_fully_merged.

            return: A CNF which links the fully merged variables
        """
        cnf = []
        for rule in self.consider_order:
            l_merged_preceding = []
            l_merged_following = []
            # Check if all preceding dependencies from other tables are merged
            for p_rule in rule.parents:
                if p_rule.table == rule.table:
                    continue
                merges = self.f2vpc_merge[p_rule, rule]
                # If a preceding rule has no merged placements, then the rule
                # cannot be fully merged
                if not merges:
                    l_merged_preceding = []
                    break
                l_merged_preceding.append(reduce_or(merges))

            # Or, check if all child dependencies from other tables are merged
            for f_rule in rule.children:
                if f_rule.table == rule.table:
                    continue
                merges = self.f2vpc_merge[rule, f_rule]
                # If a following rule has no merged placements, then the rule
                # cannot be fully merged
                if not merges:
                    l_merged_following = []
                    break
                l_merged_following.append(reduce_or(merges))

            # Now check that it is placed or is not placed but is fully merged
            l_merging = []
            if l_merged_preceding:
                l_merging.append(reduce_and(l_merged_preceding))
            if l_merged_following:
                l_merging.append(reduce_and(l_merged_following))
            if not l_merging:
                continue
            l_merging = reduce_or(l_merging)
            # fm_x <-> reduce_or
            cnf.append(self.register_fully_merged(rule) >> l_merging)
            cnf.append(l_merging >> self.register_fully_merged(rule))
        return reduce_and(cnf)

    def get_full_transformations_vars(self, rule):
        """ Returns the set of full transformations variable for a rule

            Used by SAT_pick_one_transformation

            return: A set() Variables
        """
        vars_ = set()
        if rule in self.v_fully_merged:
            vars_.add(self.v_fully_merged[rule])
        vars_.update(self.f2v_direct[rule])
        return vars_

    def SAT_pick_one_transformation(self):
        """ Ensure every rule has exactly one transformation selected """
        cnf = []
        unplaced_rules = []
        for rule in self.consider_order:
            vars_ = self.get_full_transformations_vars(rule)
            if not vars_:
                SOLVER_LOGGER.error("Absolutely no placement found for %s", rule)
                unplaced_rules.append(rule)
            self.counters.problem_space.append(len(vars_))
            cnf.append(reduce_onehot(vars_))
        if unplaced_rules:
            exit()
        return reduce_and(cnf)

    def SAT_link_transformation_to_table(self):
        """ Link a direct or merge transform to the placement table

            Creates new variables in self.v_goto_table

            foreach r in rules:
                direct -> ft
                merge -> ft
            Where ft is unique per rule and table combination

            return: The SAT expression
        """
        cnf = []
        for rule in self.consider_order:
            for v in self.f2v_direct[rule]:
                k = self.v_direct.inv[v]
                cnf.append(
                    v >> self.map_merge_table(rule, k.place.table))

        # A merge 'implies' a placement of a merged rule into a table
        for k, v in viewitems(self.v_merge):
            # For parent and child this merge puts both in this table
            for rule in k.flows:
                cnf.append(
                    v >> self.map_merge_table(rule, k.place.table))

        return reduce_and(cnf)

    def SAT_direct_and_merge_same_tables(self):
        """ Limit a rule installation to a single table, whether by merge or
            direct placement.

            return: The SAT expression
        """
        cnf = []
        for flow in self.consider_order:
            tables = [x[1] for x in viewitems(self.v_rule_merge_table)
                      if x[0][0] == flow]
            cnf.append(reduce_AMO(tables))
        return reduce_and(cnf)

    def solver_init(self):
        """ Reset and zero structures used in solving """
        # Reset old values
        super(SATSolver, self).solver_init()
        self.assign_id = 0
        self.v_direct = bidict()  # Map of direct transformations to variable id
        self.f2v_direct = defaultdict(list)  # Map of flow to variable
        self.v_merge = bidict()  # Map of rules merged with
        self.f2vpc_merge = defaultdict(list)  # Map to variables
        self.f2vp_merge = defaultdict(list)  # Map to variables
        self.f2vc_merge = defaultdict(list)  # Map to variables
        self.v_rule_merge_table = bidict()
        self.v_placement = bidict()  # Map of placements to variable id
        self.v2placements = defaultdict(list)  # Map of placements to variable id
        self.v_hit = bidict()  # Map of placements to variable id
        self.v_goto_table = bidict()  # Map of table_id to variable id
        self.v_fully_merged = bidict()  # Map of original rule to variable id
        self.v_built_in = bidict()  # Map of built-in flow rules

    def SAT_link_hit_placements(self):
        """ Creates SAT clauses to map the placements chosen to hit rules

        If rules have the same match in the same table, only the highest
        priority is hit. Given the placements selected this creates a mapping
        to hit rules, which give a unique solution.

        After every solve, the solver adds clauses to ensure this same
        combination of hit placements in not tried again.


        Note: Currently only considers rules with identical matches. Rather
        than finding all cases where a low priority rule is a subset of a
        higher priority rule.

        Consider the following rules with the same match:
        Where R1 takes precedence over R2 etc.

        R1, R2, R3, R4

        If R1 is selected, it does not matter which combination of R2-R4 is
        selected as R1 has the highest priority and packets will always hit R1.
        Similarly, so long as R1 is not selected and R2 whether R3 or R4
        is selected is irrelevant.

        return: A cnf mapping placements to hit rule variables
        """
        cnf = []
        table2place = defaultdict(list)
        for place, place_var in self.v_placement.items():
            table2place[place.table, place.match.get_wildcard()].append(
                (place_var, place))

        for group in table2place.values():
            group.sort(key=lambda x: x[1].priority)
            while group:
                place_var, place = group[0]
                clause = [place_var]
                for h_var, _ in group[1:]:
                    clause.append(-h_var)
                cnf.append(reduce_and(clause) >> self.register_hit(place_var))
                cnf.append(self.register_hit(place_var) >> reduce_and(clause))
                group = group[1:]
        return reduce_and(cnf)

    def SAT_require_table_miss(self):
        """ Creates SAT clauses to ensure every table has a table-miss rule

        forall p in placements where p has a goto instruction
            p -> t_x where p directs packets to table x
        And t_0 == True

        forall t_x in table-reached:
            t_x -> reduce_or(table-miss placments in table x)

        Table 0 always needs a default. And then any table which a rule
        goes to.

        return: A cnf requiring every reached table has a table-miss rule
        """
        tables = set([0])
        tables_built_in_miss = set()
        cnf = []
        match_all = Rule().match.get_wildcard()

        # Collect built-in table-miss rules
        built_in = Solution()
        self.add_builtins(built_in)
        for rule in built_in.get_ordered_rules():
            if rule.match.get_wildcard() == match_all:
                tables_built_in_miss.add(rule.table)

        # Each placement implies the table gone to
        for place, place_var in self.v_placement.items():
            if place.instructions.goto_table:
                cnf.append(place_var >>
                           self.register_goto_table(place.instructions.goto_table))
                tables.add(place.instructions.goto_table)

        # Always require table-miss in table 0, as all packets enter here
        tables -= tables_built_in_miss
        if 0 in tables:
            cnf.append(self.register_goto_table(0))

        for table in tables:
            places = [self.v_placement[place] for place in self.v_placement if
                      place.table == table and
                      place.match.get_wildcard() == match_all]
            cnf.append(self.register_goto_table(table) >> reduce_or(places))
        return reduce_and(cnf)

    def SAT_link_placements(self):
        """ Link transformations to actual placements in the target ruleset

            Placements must first be registered with register_placement

            Adds the following conditions:

            1) Link a transformation to its actual placements

            Forall t in transformations, Forall p in t.placements : t -> p

            2) And the reverse case, only set a placement if it has at least
               one corresponding transformation

            Forall p in placements : p -> reduce_or(transformations(p))

            return: A cnf expression
        """
        clauses = []
        place2trans = defaultdict(list)

        # 1) Picking this transformation implies the placement
        for trans, places in self.v2placements.items():
            for place in places:
                clauses.append(trans >> place)
                place2trans[place].append(trans)

        # 2) Only set a placement if it has a selected transformation
        for place, transs in place2trans.items():
            clauses.append(place >> reduce_or(transs))

        return reduce_and(clauses)

    def SAT_limit_same_priority_placements(self):
        """ Disallow placements at the same priority with different instructions

            As per OpenFlow this is undefined behaviour, as it is not clear
            which rule takes priority.

            If the instructions are different, yet functionally equivalent,
            then another transformation will exist with the exact same
            instructions.

            return: A cnf expression
        """
        clauses = []
        priority_groups = defaultdict(list)

        for place, var in self.v_placement.items():
            priority_groups[(place.table, place.priority)].append((var, place))
        for group in priority_groups.values():
            for (var_a, place_a), (var_b, place_b) in itertools.combinations(group, 2):
                if wildcard_intersect(place_a.match.get_wildcard(),
                        place_b.match.get_wildcard()):
                    if place_a.instructions == place_b.instructions:
                        continue

                    # Some TTP's have built-ins which violate this clause.
                    # Allow these; otherwise, the solve will fail.
                    if hasattr(place_a, 'built_in') and hasattr(place_b, 'built_in'):
                        continue

                    # Don't allow both placements at once
                    clauses.append(-var_a | -var_b)
        return reduce_and(clauses)

    def SAT_limit_placement_instructions(self):
        """ Disallow fully shadowed placements with different instructions

            If a placement is shadowed by a rule with different instructions
            then the solver should try pick a transformation which results in
            placements with the same instructions. If this doesn't exist then
            chances are the resulting forwarding will be wrong for traffic
            expecting to reach the shadowed rule.

            return: A cnf expression
        """
        clauses = []

        table_groups = defaultdict(list)
        for place, var in self.v_placement.items():
            table_groups[place.table].append((var, place))

        # Check for an overlap with all higher priority rules
        for table_placements in table_groups.values():
            # Sort high -> low priority
            table_placements.sort(key=lambda x: -x[1].priority)
            while table_placements:
                # pop off the end
                lo_var, lo_place = table_placements.pop()
                # Allow built-ins to be shadowed/overridden as we cannot
                # change the built-in
                if lo_place in self.v_built_in:
                    continue
                for (hi_var, hi_place) in table_placements:
                    if (lo_place.priority != hi_place.priority and
                            lo_place.match.issubset(hi_place.match) and
                            lo_place.instructions != hi_place.instructions):
                        # hi place fully overlaps lo place
                        clauses.append(-lo_var | -hi_var)

        return reduce_and(clauses)

    def SAT_limit_placement_instructions_fast(self):
        """ Disallow fully shadowed placements with different instructions

            This version only checks for exact matches, so is faster but adds
            fewer restrictions.
        """
        clauses = []
        table_match_groups = defaultdict(list)
        for place, var in self.v_placement.items():
            key = place.table, place.match.get_wildcard()
            table_match_groups[key].append((var, place))
        for group in table_match_groups.values():
            instruction_groups = defaultdict(list)
            for var, place in group:
                instruction_groups[place.instructions].append(var)
            inst_groups = list(instruction_groups.values())
            for group_a, group_b in zip(inst_groups, inst_groups[1:]):
                for var_a in group_a:
                    for var_b in group_b:
                        # TODO exclude built-in rules
                        clauses.append(-var_a | -var_b)

        return reduce_and(clauses)

    def force_options(self):
        """ Override the options specified via command line

        Options available disable features for analysis of the SAT
        Solver problem.

        The following options are available to disabled features

        NO_CONFLICT - disable adding conflicts after each iteration
        NO_HIT - disables hit placements.
            Requires: NO_CONFLICT
        NO_MISS - Ensure that reached tables are not missed
        NO_PLACEMENT_CONFLICT - Ensure that placements don't conflict
        NO_PLACEMENT - disable placements
            Requires: NO_MISS, NO_PLACEMENT_CONFLICT, NO_HIT
        NO_SAME_TABLE - Ensure that merged rules are placed in the same table
        """
        options = tuple()
        options += ("NO_CONFLICT", )
        options += ("NO_HIT", )
        options += ("NO_MISS", )
        options += ("NO_PLACEMENT_CONFLICT", )
        options += ("NO_PLACEMENT", )
        options += ("NO_SAME_TABLE", )
        self.options = options

    def validate_constraints(self):
        if "NO_HIT" in self.options:
            assert "NO_CONFLICT" in self.options
        if "NO_PLACEMENT" in self.options:
            assert "NO_HIT" in self.options
        if "NO_PLACEMENT" in self.options:
            assert "NO_MISS" in self.options
        if "NO_PLACEMENT" in self.options:
            assert "NO_PLACEMENT_CONFLICT" in self.options

    def build_SAT_expression(self, Si):
        """ Builds the original SAT expression """

        #self.force_options()
        self.validate_constraints()

        # Map all flows+placements to a Variable
        for flow in self.consider_order:
            for p in flow.placements:
                self.map_direct(flow, p)

        for k, v in viewitems(self.can_merge):
            for flow in v:
                self.map_merged(k, flow)

        # Now lets build up our sat expression.
        cnf = []

        # Map all built-in rules, and ensure they are picked
        for f in self.ttp.collect_children(TTPFlow):
            # Exclude egress tables
            if f.built_in and f.parent.number <= 60:
                res = rule_from_ttp(f)
                res.built_in = True
                cnf.append(self.map_built_in(res))

        # 2)
        # Link fully_merged variable, fully merged if merged with all
        # preceding or following rules or both
        SOLVER_LOGGER.info("Linking fully merged")
        cnf.append(self.SAT_link_fully_merged())

        # 1)
        # For every rule pick exactly one transformation, direct, split,
        # or fully merged
        SOLVER_LOGGER.info("SAT pick one")
        cnf.append(self.SAT_pick_one_transformation())

        # 3)
        # Force all merge (not fully merged), and direct placements are into
        # the same table
        if "NO_SAME_TABLE" not in self.options:
            SOLVER_LOGGER.info("Direct and merge same table")
            cnf.append(self.SAT_link_transformation_to_table())
            cnf.append(self.SAT_direct_and_merge_same_tables())

        # 4)
        # Creating mapping from rule to placements
        if "NO_PLACEMENT" not in self.options:
            SOLVER_LOGGER.info("SAT link placements")
            cnf.append(self.SAT_link_placements())

        # 5)
        # Don't allow overlapping placements at the same priority
        # with different instructions - undefined behaviour
        if "NO_PLACEMENT_CONFLICT" not in self.options:
            SOLVER_LOGGER.info("SAT limit same priority placements")
            cnf.append(self.SAT_limit_same_priority_placements())

        # 6)
        # Don't allow shadowed placements with the differing instructions
        if "NO_PLACEMENT_CONFLICT" not in self.options:
            SOLVER_LOGGER.info("SAT limit same match placements")
            cnf.append(self.SAT_limit_placement_instructions())

        # 7)
        # Require a table miss rule in every table
        if "NO_MISS" not in self.options:
            SOLVER_LOGGER.info("SAT require table miss")
            cnf.append(self.SAT_require_table_miss())

        # 8)
        # Link hit placements
        if "NO_HIT" not in self.options:
            SOLVER_LOGGER.info("SAT link hit placements")
            cnf.append(self.SAT_link_hit_placements())

        # Require all
        return reduce_and(cnf)

    def generate_transformations(self, Si, Si_single_table, Si_normalised):
        """ Gather the transformations to consider

            Applies any preprocessing and filtering. The resulting placements
            are all feed into the SATSolver.
        """
        self.compute_direct_placements(Si)
        self.can_merge = self.compute_merge_placements(Si)


    def run_solver(self, Si, all_solutions, Si_single_table, Si_normalised):
        """ A SAT solver version of rule fitting """
        super(SATSolver, self).run_solver(Si, all_solutions, Si_single_table, Si_normalised)

        with self.timers("Generating Transformations"):
            self.generate_transformations(Si, Si_single_table, Si_normalised)
            self.compress_placement_priorities(Si, self.can_merge)
            if not self.no_reactioning:
                self.reactioning(Si, self.can_merge)

        # If no placement disable code to collect placements
        if "NO_PLACEMENT" in self.options:
            self.register_placement = lambda *_a, **_b: None
        with self.timers("Build SAT Expression"):
            cnf = self.build_SAT_expression(Si)

        try:
            self.counters.sat_clauses = len(cnf.dis)
        except AttributeError:
            self.counters.sat_clauses = 0
        self.counters.sat_variables = self.assign_id
        self.counters.sat_solution_variables = len(self.collect_result_vars())
        SOLVER_LOGGER.info("Solution verification size: %i", len(Si_normalised))

        if not self.single:
            tpool = self.ThreadPool(8)
            p = functools.partial(jump_check_sln, self, Si_normalised)
            generator = tpool.imap_unordered(p,
                                             self.generate_solutions(cnf), 10)
            for sln, works in self.p_bar(generator, desc='SAT solver'):
                self.counters.iterations += 1
                if works is True:
                    tpool.terminate()
                    return sln
        else:
            generator = self.generate_solutions(cnf)
            if all_solutions == "full":
                solutions = Counter()
                bar = self.p_bar(generator, desc='SAT solver', postfix={"Soln": 0, "Uniq": 0})
            elif all_solutions == "best":
                solutions = Counter()
                best = None
                worst = None
                bar = self.p_bar(generator, desc='SAT solver', postfix={"Soln:": 0, "Best": 0, "Worst": 0})
            else:
                bar = self.p_bar(generator, desc='SAT solver')
            for solved in bar:
                self.counters.iterations += 1
                with self.timers("Solution Building"):
                    try:
                        sln = self.build_solution(solved)
                    except BadOverlap as bo:
                        self.counters.bad_overlaps += 1
                        if hasattr(bo.existing, 'built_in'):
                            e_vars = []
                        else:
                            e_vars = bo.existing.tags["vars"]
                        a_vars = bo.addition.tags["vars"]
                        for i in e_vars:
                            if str(i).startswith("m"):
                                e_vars = [reduce_and(e_vars)]
                                break

                        for i in a_vars:
                            if str(i).startswith("m"):
                                a_vars = [reduce_and(a_vars)]
                                break
                        collected = []
                        for j in e_vars:
                            for k in a_vars:
                                collected.append(-(j & k))
                        collected = reduce_and(collected)
                        self.rems = collected
                        continue

                self.counters.solutions_checked += 1
                with self.timers("Solution Compare"):
                    worked, diff = check_solution(sln, Si_normalised, diff=True)
                    if worked is True:
                        self.counters.valid_solutions += 1
                        if all_solutions == "full":
                            if self.progress:
                                bar.set_postfix_str("Soln: {:4} Uniq: {:4}".format(
                                    self.counters.valid_solutions, len(solutions)), refresh=False)
                            solutions[sln] += 1
                        elif all_solutions == "best":
                            if best is None:
                                best = sln
                                worst = sln
                            else:
                                if len(sln) > len(worst):
                                    worst = sln
                                if len(sln) < len(best):
                                    best = sln
                            if self.progress:
                                bar.set_postfix_str(
                                    "Soln: {:4} Best: {:4} Worst: {:4}".format(
                                        self.counters.valid_solutions,
                                        len(best), len(worst)), refresh=False)

                        else:
                            self.counters.unique_solutions = 1
                            return sln
                    else:
                        if "NO_CONFLICT" not in self.options:
                            with self.timers("SAT conflicts"):
                                self.rems = self.find_conflict_solution(
                                    Si_single_table, sln.to_single_table(), solved, diff)
                    # Have we hit out iteration limit
                    if self.iterations and self.counters.iterations >= self.iterations:
                        print("Reached maximum number of iterations, stopping search")
                        break
        if all_solutions:
            if self.progress:
                print("DONE:", self.counters.iterations)
            if all_solutions == "best":
                # Remain compatible and return the best and worst
                if best is not None:
                    solutions[best] += 1
                    solutions[worst] += 1
            else:
                self.counters.unique_solutions = len(solutions)
            return solutions
        print("Failed, no solutions found")
        return None

    def check_sol(self, solved, Si_normalised):
        try:
            sln = self.build_solution(solved)
        except BadOverlap:
            return None, False
        if check_solution(sln, Si_normalised):
            return sln, True
        return None, False

    def analyse_failure(self, socket, mapping):
        """ Tries to identify the flows causing the issues

            This uses a minimised clause set to find variables involved,
            which are mapped back to their original flows.
        """
        muser2_paths = [
            os.path.join(__location__, "muser2-20120821/linux_2.6_x86-64/muser2-static"),
            "muser2-static", "muser2"]
        # TODO, XXX Find the minimum failure reason
        # Minimum unsatisfiable clause(s) (MUS)
        socket.send_multipart([b"o"])
        ret = socket.recv_multipart()[0]
        with tempfile.NamedTemporaryFile() as f:
            f.write(ret)
            f.flush()
            outputpath = "/tmp/muser_" + str(os.getpid())
            exceptions = []
            for muser_path in muser2_paths:
                try:
                    proc = subprocess.Popen([muser_path, "-wf",
                                             outputpath, f.name])
                    proc.wait()
                    break
                except OSError as e:
                    exceptions.append(e)
            else:
                attempts = map(": ".join, zip(muser2_paths, map(str, exceptions)))
                raise OSError("Could not run or find muser2 executable\n"
                              "Attempted: \n" + "\n".join(attempts))
            variables = set()
            with open(outputpath + ".cnf") as of:
                content = of.readlines()[1:]
                for l in content:
                    for var in l.split(" ")[:-1]:
                        mapped = mapping.inv[abs(int(var))]
                        if int(var) < 0:
                            print("-{}".format(mapped), end=' ')
                        else:
                            print("{}".format(mapped), end=' ')
                        variables.add(mapped)
                    print()
            print("Where:")
            for v in variables:
                if v.startswith('d'):
                    t = self.v_direct.inv[Variable(v)]
                    print(v, '= direct', t)
                elif v.startswith('mt'):
                    t = self.v_rule_merge_table.inv[Variable(v)]
                    print(v, '= merge table', t)
                elif v.startswith('m'):
                    t = self.v_merge.inv[Variable(v)]
                    print(v, '= merge', t)
                elif v.startswith('s'):
                    t = self.v_split.inv[Variable(v)]
                    print(v, '= split', t)
                elif v.startswith('b'):
                    t = self.v_built_in.inv[Variable(v)]
                    print(v, '= built_in', t)
                elif v.startswith('p'):
                    t = self.v_placement.inv[Variable(v)]
                    print(v, '= placement', t)

    def generate_solutions(self, cnf):
        timer = self.timers("SAT Solving Time")
        timer.start()
        proc = None
        ctx = None
        socket = None
        ipc_name = "dminisat" + str(os.getpid())

        minisat_paths = [os.path.join(__location__, "minisat-zmq"),
                         "minisat-zmq"]
        try:
            with self.timers("Init SAT Solver"):
                path = "ipc:///tmp/" + ipc_name
                ctx = zmq.Context()
                socket = ctx.socket(zmq.REQ)
                # Discard all unsent messages when closed
                socket.setsockopt(zmq.LINGER, 0)
                socket.bind(path)
                # Save about 100ms having the bound socket ready, and minisat
                # connect to use; the connection goes through on its first try.
                # Try find and execute the minisat executable

                exceptions = []
                for minisat_path in minisat_paths:
                    try:
                        proc = subprocess.Popen([minisat_path, "-ipc-name=" + ipc_name],
                                                stdin=None,
                                                stdout=None)
                        break
                    except OSError as e:
                        exceptions.append(e)
                else:  # Could not find or run the minisat executable
                    attempts = map(": ".join, zip(minisat_paths, map(str, exceptions)))
                    raise OSError("Could not run or find minisat-zmq executable\n"
                                  "Attempted: \n" +
                                  "\n".join(attempts))

                """dnf = satispy.io.dimacs_cnf.DimacsCnf()
                as_str = dnf.tostring(cnf)
                with open("/tmp/1_dimacs.d", 'w') as out:
                    out.write(as_str)
                for k, v in viewitems(dnf.varname_dict):
                    mapping[k.name] = int(v)

                socket.send_multipart([b"d", "/tmp/1_dimacs.d"])
                assert socket.recv_multipart() == [b"OK"]"""

                s = []
                clauses, mapping = to_dimacs(cnf)
                socket.send_multipart([b"r", b" 0 ".join(clauses)])
                assert socket.recv_multipart() == [b"OK"]

                # Find those we care about
                # It is possible that simplification has removed
                # the vars so add any removed back
                for v in self.collect_result_vars() + self.get_transformation_vars():
                    if variable_name(v) not in mapping:
                        mapping[variable_name(v)] = len(mapping) + 1

                # Register placement vars
                s = [str(mapping[variable_name(v)]).encode('ascii') for v in self.collect_result_vars()]
                socket.send_multipart([b"p", b" ".join(s)])
                assert socket.recv_multipart() == [b"OK"]

                # Register transformation vars
                s += [str(mapping[variable_name(v)]).encode('ascii') for v in self.get_transformation_vars()]
                #socket.send_multipart([b"c", b" ".join(s)])
                #assert socket.recv_multipart() == [b"OK"]

            while True:
                socket.send_multipart([b"s"])
                ret = socket.recv_multipart()[0]
                if ret == b"UNSAT":
                    if self.print_failure:
                        self.analyse_failure(socket, mapping)
                    return
                positives = set(ret.split(b" "))
                solution = FakeSln()
                for k, v in viewitems(mapping):
                    if str(v).encode('ascii') in positives:
                        solution[Variable(k)] = True
                    else:
                        solution[Variable(k)] = False
                solution.success = True
                # Only count generator time, not the yeilded result
                timer.stop()
                yield solution
                timer.start()
                if self.rems is not None:
                    s = []
                    self.counters.sat_placement_excluded += 1
                    try:
                        self.counters.sat_clauses_added += len(self.rems.dis)
                    except AttributeError:
                        pass
                    clauses, mapping = to_dimacs(self.rems, mapping)
                    socket.send_multipart([b"r", b" 0 ".join(clauses)])
                    assert socket.recv_multipart() == [b"OK"]

        finally:
            # Cleanup, called when out of scope or finished, or erred
            # Make sure we close the process
            if socket is not None:
                try:
                    socket.send_multipart([b"f"], flags=zmq.NOBLOCK)
                except zmq.ZMQError:
                    # If not connected this will fail
                    pass
                else:
                    # Read the response
                    socket.recv_multipart()
                socket.close()
            if ctx is not None:
                ctx.term()
            if proc is not None:
                proc.kill()
                proc.wait()
            # Might be running, might not depends if an excepted occurred
            # within the generator or outside
            if timer.running():
                timer.stop()

    def boolalg_generate_solutions(self, cnf):
        """
        Use the built-in boolalg library generator

        This is slow, as it does not incrementally add to the solution
        """
        while True:
            cnf.simplify()
            solved, sln = cnf.sat()

            if solved:
                # Those that don't matter are not returned
                # We'll set these to false
                for v in self.collect_result_vars():
                    if v not in sln:
                        sln[v] = False
                yield sln
            else:
                return

            solution_vars = self.collect_result(sln)
            cnf &= -reduce_and(solution_vars)
            if self.rems is not None:
                cnf &= self.rems
                self.rems = None

    def old_generate_solutions(self, cnf):
        """ A generator of solutions """
        solver = Minisat()
        while True:
            solved = solver.solve(cnf)
            self.blah = cnf
            if solved.success is False:
                # DONE
                return
            yield solved
            solution_vars = self.collect_result(solved)
            cnf &= -reduce_and(solution_vars)
            if self.rems is not None:
                cnf &= self.rems
                self.rems = None

    def collect_result_vars(self):
        """ Returns a list of variables which must be changed by the next
            solution.

            I.e. The solver will put a clause in to prohibit this combination
                 again.
        """
        if "NO_PLACEMENT" in self.options:
            return self.get_transformation_vars()
        if "NO_HIT" in self.options:
            return list(self.v_placement.values())
        return list(self.v_hit.values())

    def collect_result(self, solved):
        """ Collects the resulting variables
            solved: The result of minisat
            return: The list of solution defining Variables set or unset.
                    i.e. Placement and merge variables.
        """
        return [v if solved[v] else -v for v in self.collect_result_vars()]

    def add_flow_to_solution(self, flow, sln, solved):
        """ Adds a flow to a solution from the SAT solvers result

            This is per flow to allow different ordering to be explored.

            Once placed, each solved variable is changed from True to 1 in solved
            this provides a sanity check that all variables are correctly considered.
        """
        # Where do we add this flow?
        placement = [self.v_direct.inv[v] for v in
                     self.f2v_direct[flow] if solved[v]]
        if len(placement) == 1:
            solved[self.v_direct[placement[0]]] = 1
            p = placement[0].place.copy()
            assert hasattr(flow, "children")
            sln.add([p], flow, {"flows": [flow],
                                "vars": [self.v_direct[placement[0]]]})
        else:
            # There should be exactly one direct placement
            assert len(placement) != 1
        # Now lets do merges
        for v in self.f2vp_merge[flow]:
            k = self.v_merge.inv[v]
            if solved[v]:
                solved[v] = 1
                sln.add([k.place], k.flows[-1],
                        {"flows": list(k.flows), "vars": [v]})

    def add_builtins(self, sln):
        """ Add all default built-in/hardcoded flows to a solution """
        for f in self.ttp.collect_children(TTPFlow):
            # Exclude egress tables
            if f.built_in and f.parent.number <= 60:
                res = rule_from_ttp(f)
                res.built_in = True
                # Allow bad overlaps
                sln.add([res], None, {"built_in": [f]}, True)

    def build_solution(self, solved):
        """ Build a solution from the output,
            solved: The result from minisat
            return: A solution built from the input
        """
        sln = Solution()
        sln.solved = solved
        # Add built-ins
        self.add_builtins(sln)
        for flow in self.consider_order:
            self.add_flow_to_solution(flow, sln, solved)

        # Sanity check no Trues should be left
        assert not {x for x, y in solved.items() if y is True}.intersection(
                self.get_transformation_vars())
        return sln

    def get_transformation_vars(self, rule=None):
        """ Returns all transformation SAT variables for a Rule

            rule: Optional, A rule to filter the variables from
            return: A iterable of SAT Variables
        """
        if rule is None:
            return list(self.v_direct.values()) + list(self.v_merge.values())
        return (self.f2v_direct[rule] + self.f2vc_merge[rule] +
                self.f2vp_merge[rule])

    def get_solution_vars(self, rule):
        """ Returns SAT variables to consider when building a solution

            Compared to get_transformation_vars, this only returns variables
            which should be added to a solution when considering this rule.
            I.e. to match the behaviour of add_flow_to_solution.
            Used by apply_solution_to_original

            rule: The Rule being added to the solution
            return: A iterable of SAT Variables
        """
        return self.f2v_direct[rule] + self.f2vp_merge[rule]

    def find_conflict_solution(self, Si, sln, solved, diff):
        """ Take a solution, look at the conflicting clauses and do not let
            that sequence happen again. It does limit the solver putting stuff
            in the middle. But anyway should still catch most.

            Si: The input ruleset as a single table
            sln: The solution we are comparing
            solved: The SAT solver result
            diff: The difference between the rulesets
        """
        cnf = []
        conflicts = find_conflicting_paths(diff, Si, sln, no_sort=True)
        for orig_path, new_conflicts in conflicts.items():
            v_not = []
            new_conflicts = {rule for path in new_conflicts for rule in path}
            # Transformations of rules in the original path
            for rule in orig_path:
                vars_ = [v for v in self.get_transformation_vars(rule)
                         if solved[v]]
                assert vars_
                v_not += vars_
            # The corresponding hit placements in the result
            for rule in new_conflicts:
                v_not += [self.v_hit[self.v_placement[rule]]]
                continue

            cnf.append(-(reduce_and(v_not)))
            assert v_not
        return reduce_and(cnf)

    def debug_input_placement(self, solved, flow):
        """ Print the merges and placements of a flow rule """
        print("----DEBUG----")
        print("Original ---")
        print(flow)

        def indent(i, offset='\t'):
            return offset + ("\n"+offset).join(str(i).splitlines())

        c_placements = [v for v in self.f2v_direct[flow] if solved[v]]
        assert len(c_placements) <= 1
        print("  *Placements selected", len(c_placements), "of",
                   len(self.f2v_direct[flow]))
        for v in c_placements:
            k = self.v_direct.inv[v]
            print("    ", v)
            print(indent(k.place, "      "))
        c_cmerged = [v for v in self.f2vc_merged[flow] if solved[v]]
        print("  *Child merge", len(c_cmerged), "of",
                   len(self.f2vc_merged[flow]))
        for v in c_cmerged:
            k = self.v_merge.inv[v]
            print("    ", v)
            print(indent(k.parent, "      "))
        c_pmerged = [v for v in self.f2vp_merge[flow] if solved[v]]
        print("  *Parent merge", len(c_pmerged), "of",
                   len(self.f2vp_merge[flow]))
        for v in c_pmerged:
            k = self.v_merge.inv[v]
            print("    ", v, " Merged with: ")
            print(indent(k.child, "      "))
        c_split = [v for v in self.f2v_split[flow] if solved[v]]
        print("  *Split placements", len(c_split), "of",
                   len(self.f2v_split[flow]))
        for v in c_split:
            k = self.v_split.inv[v]
            print("    ", v)
            print(indent(k.split, "      "))

        print("----DEBUG----")

    def debug_solved(self, Si, solved):
        for flow in Si:
            self.debug_input_placement(solved, flow)

    @staticmethod
    def flt(a):
        ret = []
        for x in a:
            if isinstance(x, tuple):
                ret += SATSolver.flt(x[0]) + SATSolver.flt(x[1])
            else:
                ret += [x]
        return ret


    def pre_solve(self, ruleset):
        """ The pre_solve hook """
        if self.no_compression:
            dd = ruleset
        else:
            with self.timers("Compress Ruleset"):
                self._pre_compression = ruleset
                dd, self.DD_groups = compress_ruleset(ruleset)
        return super(SATSolver, self).pre_solve(dd)

    def post_solve(self, result):
        """ Hook to reverse the compression in pre_solve """
        result = super(SATSolver, self).post_solve(result)
        if self.no_compression:
            return result
        with self.timers("Applying Model"):
            return self.apply_solution_to_original(result, self._pre_compression)

    def refit(self, rule, model):
        """ Refits a new flow rule into an existing placement

            rule: The flow rule to place
            model: The model placement, to match
            return: Rule rewritten to fit the placement described by model
                    Otherwise throws an exception.
        """
        return TTPFlow.apply(rule, model)

    def apply_solution_to_original(self, result, original_input):
        """ Apply the solution found on a compressed ruleset to full ruleset

            result: A ruleset. The solution to a compressed ruleset
            original_input: The original full input ruleset
            return: A ruleset. The solution generalised back to the original
                    full ruleset.
        """
        new_result = Solution()
        self.add_builtins(new_result)
        merged = set()
        # Urrgh rehash these as have changed
        DD_groups = {}
        for k, v in viewitems(self.DD_groups):
            DD_groups[k] = v
        self.DD_groups = DD_groups
        for installed_rule in self.consider_order:
            all_rules = self.DD_groups[installed_rule]
            # Need to find where this got placed
            place_vars = [x for x in self.get_solution_vars(installed_rule)
                          if result.solved[x]]
            for rule in all_rules:
                for placement in place_vars:
                    if placement in self.v_direct.inv:
                        # Skip if already in compressed solution
                        if rule == installed_rule:
                            continue
                        orig_place = self.v_direct.inv[placement]
                        assert isinstance(orig_place.place, Rule)
                        place = self.refit(rule, orig_place.place)
                        new_result.add([place], rule)
                    elif placement in self.v_merge.inv:
                        if placement in merged:
                            # We might have already done this one
                            continue
                        merged.add(placement)
                        orig_merge = self.v_merge.inv[placement]
                        merge = orig_merge.place

                        def _walk_them(items):
                            i = items[0]
                            if len(items) == 1:
                                return [[x] for x in self.DD_groups[i]]
                            collection = []
                            assert i in self.DD_groups
                            for rule_ in self.DD_groups[i]:
                                collection += [[rule_] + x for x in
                                               _walk_them(items[1:])]
                            return collection
                        for mergees in _walk_them(orig_merge.flows):
                            # Skip if already in compressed solution
                            if tuple(mergees) == orig_merge.flows:
                                continue
                            merge_r = mergees[0].merge(mergees[1])
                            for rule in mergees[2:]:
                                merge_r = merge_r.merge(rule)
                            merge_r = self.refit(merge_r, merge)
                            try:
                                new_result.add([merge_r], rule)
                            except BadOverlap:
                                # debug()
                                raise
                        pass
                    elif placement in self.v_split.inv:
                        orig_split = self.v_split.inv[placement]
                        frw = rule.copy()
                        for x in orig_split.split:
                            if hasattr(x, 'built_in'):
                                place = x
                            elif hasattr(x, "reactioned"):
                                # Find how it was reactioned i.e. from what flow
                                # Find flows in group and merge
                                def _filter(rule, n):
                                    mask = get_wildcard_mask(x.match.get_wildcard())
                                    mask = mask | (mask << 1)
                                    remasked = n.match.get_wildcard() | mask
                                    return wildcard_intersect(rule.match.get_wildcard(), remasked)

                                a = [n for n in self.DD_groups[x.reactioned]
                                     if _filter(rule, n)]
                                assert a  # Verify we found an option
                                try:
                                    place = self.refit(a[0], x)
                                except Exception:
                                    #debug()
                                    raise
                            else:
                                # Refit to x
                                try:
                                    place = self.refit(rule, x)
                                except Exception:
                                    # debug()
                                    raise
                            new_result.add([place], rule)
                    else:
                        raise NotImplementedError(
                            "Placement type %s not implemented" % placement)
        # Add the rules from the compressed solution, inc. extra table miss drop rules
        for rule in result.get_ordered_rules():
            if 'flow' not in rule.tags:
                new_result.add([rule], None)
            else:
                new_result.add([rule], rule.tags['flow'])
        # Finally check that the new solution is still equivalent to the input
        with self.timers("Verifying Solution"):
            input_single = to_single_table_scaled(original_input)
            input_norm = normalise(input_single)
            new_norm = normalise(new_result.to_single_table())
            if check_equal(input_norm, new_norm):
                return new_result
        SOLVER_LOGGER.error(
            "Failed to apply the compressed model back to the original ruleset")
        return None


class SplitSATSolver(SATSolver):
    v_split = None  # (flow, places) -> V
    f2v_split = None  # (flow) -> Vs

    def map_split(self, rule, places):
        """ Maps a split transformation to a variable in the solver

        If already registered this returns the existing Variable

        rule: The original rule
        places: The transformed split placements
        return: The variable representing this transformation in the solver
        """
        split = TransSplit(rule, places)
        if split in self.v_split:
            return self.v_split[split]
        self.assign_id += 1
        split_var = Variable("s" + str(self.assign_id))
        self.v_split[split] = split_var
        self.f2v_split[rule].append(split_var)
        for place in places:
            self.register_placement(split_var, place)
        return split_var

    def get_full_transformations_vars(self, rule):
        vars_ = super(SplitSATSolver, self).get_full_transformations_vars(rule)
        vars_.update(self.f2v_split[rule])
        return vars_

    def solver_init(self):
        super(SplitSATSolver, self).solver_init()
        self.v_split = bidict()  # Map of splits
        self.f2v_split = defaultdict(list)  # Rules to splits

    def generate_transformations(self, Si, Si_single_table, Si_normalised):
        self.compute_split_placements(Si, Si_normalised)
        return super(SplitSATSolver, self).generate_transformations(Si, Si_single_table, Si_normalised)

    def build_SAT_expression(self, Si):
        for flow in self.consider_order:
            # Map splits
            flow.split_placements = list(set(flow.split_placements))
            for split in flow.split_placements:
                self.map_split(flow, split)

        return super(SplitSATSolver, self).build_SAT_expression(Si)

    def collect_result(self, solved):
        solution_vars = super(SplitSATSolver, self).collect_result(solved)
        for v in viewvalues(self.v_split):
            if solved[v]:
                solution_vars.append(v)
            else:
                solution_vars.append(-v)
        return solution_vars

    def get_transformation_vars(self, rule=None):
        res = super(SplitSATSolver, self).get_transformation_vars(rule)
        if rule is None:
            return res + list(self.v_split.values())
        return res + self.f2v_split[rule]

    def get_solution_vars(self, rule):
        return (super(SplitSATSolver, self).get_solution_vars(rule) +
                self.f2v_split[rule])

    def add_flow_to_solution(self, flow, sln, solved):
        super(SplitSATSolver, self).add_flow_to_solution(flow, sln, solved)
        # A split placement
        for v in self.f2v_split[flow]:
            k = self.v_split.inv[v]
            if solved[v]:
                solved[v] = 1
                sln.add(k.split, flow, {"flows": [flow], "vars": [v]})


class SingleSATSolver(SplitSATSolver):
    """ Same as SplitSATSover except converts input to a single table first """

    def ruleset_hook(self, ruleset):
        """ Converts the input to a single table before solving. """
        ruleset = super(SingleSATSolver, self).ruleset_hook(ruleset)
        rules = to_single_table_scaled(ruleset)
        # Rules come back ordered, ensure priorities don't overlap if match
        # portion overlaps, as this is undefined. If they do, decrease priority.
        priorities = sorted({(f.priority for f in rules)}, reverse=True)
        last_priority = None
        for priority in priorities:
            # Check for overlap
            subset = [r for r in rules if r.priority == priority]
            # If we have moved down to far
            if last_priority is not None and last_priority <= priority:
                for r in subset:
                    r.priority = last_priority-1
            offset = 1
            while offset < len(subset):
                against = subset[:offset]
                wc = subset[offset].match.get_wildcard()
                for r in against:
                    if wildcard_intersect(r.match.get_wildcard(), wc):
                        # Demote priority relative to the overlap rule
                        subset[offset].priority = r.priority - 1
                        last_priority = subset[offset].priority
                offset += 1
        # Make sure no priority is less than 0, add an offset to all
        if last_priority is not None and (last_priority < 0 or
                                          rules[-1].priority < 0):
            offset = -min(last_priority, rules[-1].priority)
            for x in rules:
                x.priority += offset

        # Remove any unreachable rules from the ruleset:
        rules = sorted(rules, key=lambda a: -a.priority)

        bdd_accumulated = BDD()
        new_ruleset = []
        for rule in rules:
            bdd = wc_to_BDD(rule.match.get_wildcard(), "1", "1")
            next_bdd = bdd_accumulated + bdd
            if next_bdd != bdd_accumulated:
                new_ruleset.append(rule)
            bdd_accumulated = next_bdd

        rules = new_ruleset

        return rules
