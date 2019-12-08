#!/usr/bin/python
""" Runs a rule-fitting solver with the options specified
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
import argparse
from .search import SearchSolver
from .SAT import SplitSATSolver, SATSolver, SingleSATSolver
from .genetic import GeneticSolver
from .util.timer import TimerHierarchy


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Transforms an OpenFlow ruleset to fit a fixed-function pipeline')
    parser.add_argument('-t', '--time', help='Collect timing information',
                        action='store_true')
    parser.add_argument('-d', '--dummy',
                        help='Use dummy multiprocessing i.e. threading',
                        action='store_true')
    parser.add_argument('-s', '--single',
                        help='Use the single threaded solver',
                        action='store_true')
    parser.add_argument('capture',
                        help='A file of a pickled set of flow rules, either'
                             ' a full state capture or list of flow stats')
    parser.add_argument('ttp',
                        help='A JSON Table Type Pattern description')
    parser.add_argument('-a', '--algorithm', help='The algorithm to use',
                        choices=['Search', 'SAT', 'SSAT', 'SingleSAT', 'Genetic'],
                        default='SingleSAT')
    parser.add_argument('-p', '--print-failure',
                        help='Prints additional information about a failure',
                        action='store_true')
    parser.add_argument('--progress',
                        help="Track progress throughout the solver, adds progress"
                             " bars to loops.",
                        action='store_true')
    parser.add_argument('-l', '--log-level',
                        default='INFO',
                        help="The solvers logging level",
                        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'])
    parser.add_argument('--ttp-log-level',
                        default='INFO',
                        help="The logging level used when loading the TTP",
                        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'])
    parser.add_argument('-C', '--no-compression', default=False, action='store_true',
                        help="Disable compression of the input ruleset.")
    full_group = parser.add_mutually_exclusive_group()
    full_group.add_argument('-f', '--full', default=False, action='store_true',
                            help="Collect all valid results")
    full_group.add_argument('-b', '--best', default=False, action='store_true',
                            help="Check all results, only save the best and worst")
    parser.add_argument('-i', '--iterations', default=0, type=int,
                        help="Limit the iterations of the solver")
    parser.add_argument('-M', '--no-merge', default=False, action='store_true',
                        help="Disable merge placements")
    parser.add_argument('-R', '--no-reactioning', default=False, action='store_true',
                        help="Disable reactioning. Reactioning tries to replace"
                             " a placement with a placement from another rule "
                             "with the same match but different actions."
                             " See ofsolver.solver.Solver.reactioning")
    parser.add_argument('-G', '--no-generalisation', default=False, action='store_true',
                        help="Disable generalisation. Generalisation creates rules with less"
                             " specific matches. See ofsolver.solver.valid_generalisation.")
    parser.add_argument('-o', '--option', default=[], type=str, dest='options',
                        choices=["NO_CONFLICT", "NO_HIT", "NO_MISS",
                                 "NO_PLACEMENT", "NO_PLACEMENT_CONFLICT",
                                 "NO_SAME_TABLE"],
                        action='append',
                        help='Additional solver specific options')
    return parser.parse_args()


def main():
    args = parse_arguments()

    solver_class = None
    if args.algorithm == 'SSAT':
        solver_class = SplitSATSolver
    elif args.algorithm == 'SAT':
        solver_class = SATSolver
    elif args.algorithm == 'Search':
        solver_class = SearchSolver
    elif args.algorithm == 'SingleSAT':
        solver_class = SingleSATSolver
    elif args.algorithm == 'Genetic':
        solver_class = GeneticSolver
    timers = TimerHierarchy("Total Runtime")
    with timers.get_base():
        if solver_class is not None:
            solver = solver_class(args.ttp, timers, args.single, args.dummy,
                                  args.print_failure, args.progress,
                                  args.log_level, args.ttp_log_level,
                                  args.no_compression, args.no_merge,
                                  args.no_reactioning, args.no_generalisation,
                                  args.options, args.iterations)
            full = None
            if args.full:
                full = "full"
            elif args.best:
                full = "best"
            res = set()
            res = solver.solve(args.capture, full)
            if args.full or args.best:
                if res:
                    best = min(res, key=len)
                    worst = max(res, key=len)
                    print(best)
                    if args.full:
                        print("Found:", len(res))
                    print("Best solution:", len(best))
                    print("Worst solution:", len(worst))
                else:
                    print("No solutions found")
            else:
                print(res)
    if args.time:
        print()
        print(solver.counters)
        print()
        print("--- Timers ---")
        print(timers)


if __name__ == '__main__':
    main()
