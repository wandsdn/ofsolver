#!/usr/bin/python
""" A genertic alogrithm based rule-fitting solver implementation

    This is very early experimental code which I have not fully tested.
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
import random

from deap import base, creator, tools, algorithms

from .SAT import SingleSATSolver, SATSolver, BadOverlap
from .solver import (SOLVER_LOGGER,
                     check_solution, find_conflicting_paths)


def eaSimple2(population, toolbox, cxpb, mutpb, ngen, stats=None,
              halloffame=None, verbose=__debug__):
    """
    From deap.algorithms.py
    Modified to break early if a valid solution is found

    This algorithm reproduce the simplest evolutionary algorithm as
    presented in chapter 7 of [Back2000]_.
    :param population: A list of individuals.
    :param toolbox: A :class:`~deap.base.Toolbox` that contains the evolution
                    operators.
    :param cxpb: The probability of mating two individuals.
    :param mutpb: The probability of mutating an individual.
    :param ngen: The number of generation.
    :param stats: A :class:`~deap.tools.Statistics` object that is updated
                  inplace, optional.
    :param halloffame: A :class:`~deap.tools.HallOfFame` object that will
                       contain the best individuals, optional.
    :param verbose: Whether or not to log the statistics.
    :returns: The final population
    :returns: A class:`~deap.tools.Logbook` with the statistics of the
              evolution
    The algorithm takes in a population and evolves it in place using the
    :meth:`varAnd` method. It returns the optimized population and a
    :class:`~deap.tools.Logbook` with the statistics of the evolution. The
    logbook will contain the generation number, the number of evalutions for
    each generation and the statistics if a :class:`~deap.tools.Statistics` is
    given as argument. The *cxpb* and *mutpb* arguments are passed to the
    :func:`varAnd` function. The pseudocode goes as follow ::
        evaluate(population)
        for g in range(ngen):
            population = select(population, len(population))
            offspring = varAnd(population, toolbox, cxpb, mutpb)
            evaluate(offspring)
            population = offspring
    As stated in the pseudocode above, the algorithm goes as follow. First, it
    evaluates the individuals with an invalid fitness. Second, it enters the
    generational loop where the selection procedure is applied to entirely
    replace the parental population. The 1:1 replacement ratio of this
    algorithm **requires** the selection procedure to be stochastic and to
    select multiple times the same individual, for example,
    :func:`~deap.tools.selTournament` and :func:`~deap.tools.selRoulette`.
    Third, it applies the :func:`varAnd` function to produce the next
    generation population. Fourth, it evaluates the new individuals and
    compute the statistics on this population. Finally, when *ngen*
    generations are done, the algorithm returns a tuple with the final
    population and a :class:`~deap.tools.Logbook` of the evolution.
    .. note::
        Using a non-stochastic selection method will result in no selection as
        the operator selects *n* individuals from a pool of *n*.
    This function expects the :meth:`toolbox.mate`, :meth:`toolbox.mutate`,
    :meth:`toolbox.select` and :meth:`toolbox.evaluate` aliases to be
    registered in the toolbox.
    .. [Back2000] Back, Fogel and Michalewicz, "Evolutionary Computation 1 :
       Basic Algorithms and Operators", 2000.
    """
    logbook = tools.Logbook()
    logbook.header = ['gen', 'nevals'] + (stats.fields if stats else [])

    # Evaluate the individuals with an invalid fitness
    invalid_ind = [ind for ind in population if not ind.fitness.valid]
    fitnesses = toolbox.map(toolbox.evaluate, invalid_ind)
    for ind, fit in zip(invalid_ind, fitnesses):
        ind.fitness.values = fit

    if halloffame is not None:
        halloffame.update(population)

    record = stats.compile(population) if stats else {}
    logbook.record(gen=0, nevals=len(invalid_ind), **record)
    if verbose:
        print(logbook.stream)

    # Begin the generational process
    for gen in range(1, ngen + 1):
        # Select the next generation individuals
        offspring = toolbox.select(population, len(population))

        # Vary the pool of individuals
        offspring = algorithms.varAnd(offspring, toolbox, cxpb, mutpb)

        # Evaluate the individuals with an invalid fitness
        invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
        fitnesses = toolbox.map(toolbox.evaluate, invalid_ind)
        for ind, fit in zip(invalid_ind, fitnesses):
            ind.fitness.values = fit

        # Update the hall of fame with the generated individuals
        if halloffame is not None:
            halloffame.update(offspring)

        # Replace the current population by the offspring
        population[:] = offspring

        # Append the current generation statistics to the logbook
        record = stats.compile(population) if stats else {}
        logbook.record(gen=gen, nevals=len(invalid_ind), **record)
        if verbose:
            print(logbook.stream)
        if min([i.fitness.values[0] for i in offspring]) < 100000:
            break
    return population, logbook


class GeneticSolver(SingleSATSolver):

    def run_solver(self, Si, all_solutions, single_Si, nsingle_Si):
        """ Don't actually use SAT use genetic deap """
        self.compute_split_placements(Si, nsingle_Si)

        # Purposely use the wrong super class here
        super(SATSolver, self).run_solver(Si, all_solutions, single_Si, nsingle_Si)

        with self.timers("Generating Transformations"):
            self.generate_transformations(Si, single_Si, nsingle_Si)
            self.compress_placement_priorities(Si, self.can_merge)
            if not self.no_reactioning:
                self.reactioning(Si, self.can_merge)

        for rule in self.consider_order:
            rule.split_placements = list(set(rule.split_placements))
            for sp in rule.split_placements:
                self.map_split(rule, sp)

        # So we build up a pick of each split placement for each flow

        creator.create("FitnessMin", base.Fitness, weights=(-1.0,))
        creator.create("Individual", list, fitness=creator.FitnessMin)

        IND_SIZE = len(Si)
        MAX_RANDOMS = [len(x.split_placements) for x in Si]

        SOLVER_LOGGER.info("Number of split placements: %s", MAX_RANDOMS)

        if min(MAX_RANDOMS) == 0:
            assert min(MAX_RANDOMS) != 0

        def random_individual(clas):
            l = clas()
            for x in Si:
                i = x.split_placements
                l.append(random.randint(0, len(i)-1))
            return l

        def mutate(mutant):
            i = random.randint(0, len(mutant)-1)
            mutant[i] = random.randint(0, MAX_RANDOMS[i]-1)
            return (mutant,)

        SOLVER_LOGGER.info("Solution verification size: %i", len(nsingle_Si))

        def evaluate(i):
            try:
                i.items = tuple
                sln = self.build_solution(i)
                worked, diff = check_solution(sln, nsingle_Si, diff=True)
            except BadOverlap:
                return (1000000,)
            if worked:
                return (len(sln),)
            r = find_conflicting_paths(diff, Si, sln.get_ordered_rules())
            return (100000 + len(r),)

        toolbox = base.Toolbox()

        toolbox.register("individual", random_individual, creator.Individual)
        toolbox.register("population", tools.initRepeat, list,
                         toolbox.individual)

        toolbox.register("mate", tools.cxTwoPoint)
        toolbox.register("mutate", mutate)
        toolbox.register("select", tools.selTournament, tournsize=3)
        toolbox.register("evaluate", evaluate)

        pop = toolbox.population(10)
        hof = tools.HallOfFame(5)
        stats = eaSimple2(pop, toolbox, 0.8, 0.5, 1000, halloffame=hof)

        try:
            eva = evaluate(hof[0])[0]
            res = self.build_solution(hof[0])
        except Exception:
            eva = 1000000

        if eva < 10000:
            #Fake a selection
            # Solved
            res.solved = {}
            for i, f in enumerate(Si):
                split = self.v_split[(f, f.split_placements[hof[0][i]])]
                res.solved[split] = True

            for v in self.v_split.values():
                if v not in res.solved:
                    res.solved[v] = False

            return res
        return None

    def add_flow_to_solution(self, flow, sln, ind):
        # A split placement
        i = self.consider_order.index(flow)
        sln.add(flow.split_placements[ind[i]], flow, {"flows": [flow]})
