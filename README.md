A rule-fitting solver, which takes an OpenFlow 1.3 ruleset and transforms it to fit a new constrained fixed-function pipeline.


### Running

The main executable is ```ofsolver``` and is installed to
/usr/bin in your python environment.

To use the recommended settings run:
```
ofsolver --progress ruleset.pickle ttp.json
```
Where ```ttp.json``` is a [Table Type Pattern](https://www.opennetworking.org/wp-content/uploads/2013/04/OpenFlow%20Table%20Type%20Patterns%20v1.0.pdf) encoded as JSON and  ```ruleset.pickle``` is in the format supported by [ofequivalence](https://github.com/wandsdn/ofequivalence). You can collect a ruleset in this format from a switch using this script: [collect_state.py](https://github.com/wandsdn/ofequivalence/blob/master/scripts/collect_state.py).

There are some sample rulesets and patterns in ```tests/```, e.g.:
```
ofsolver --progress tests/rulesets/sample_rules.pickle tests/ttps/test_pipeline2.json
```

For more advanced settings check --help:
 ```ofsolver --help
usage: ofsolver [-h] [-t] [-d] [-s] [-a {Search,SAT,SSAT,SingleSAT,Genetic}]
                [-p] [--progress] [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]
                [--ttp-log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}] [-C]
                [-f | -b] [-i ITERATIONS] [-M] [-R] [-G]
                [-o {NO_CONFLICT,NO_HIT,NO_MISS,NO_PLACEMENT,NO_PLACEMENT_CONFLICT,NO_SAME_TABLE}]
                capture ttp

Transforms an OpenFlow ruleset to fit a fixed-function pipeline

positional arguments:
  capture               A file of a pickled set of flow rules, either a full
                        state capture or list of flow stats
  ttp                   A JSON Table Type Pattern description

optional arguments:
  -h, --help            show this help message and exit
  -t, --time            Collect timing information
  -d, --dummy           Use dummy multiprocessing i.e. threading
  -s, --single          Use the single threaded solver
  -a {Search,SAT,SSAT,SingleSAT,Genetic}, --algorithm {Search,SAT,SSAT,SingleSAT,Genetic}
                        The algorithm to use
  -p, --print-failure   Prints additional information about a failure
  --progress            Track progress throughout the solver, adds progress
                        bars to loops.
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        The solvers logging level
  --ttp-log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        The logging level used when loading the TTP
  -C, --no-compression  Disable compression of the input ruleset.
  -f, --full            Collect all valid results
  -b, --best            Check all results, only save the best and worst
  -i ITERATIONS, --iterations ITERATIONS
                        Limit the iterations of the solver
  -M, --no-merge        Disable merge placements
  -R, --no-reactioning  Disable reactioning. Reactioning tries to replace a
                        placement with a placement from another rule with the
                        same match but different actions. See
                        ofsolver.solver.Solver.reactioning
  -G, --no-generalisation
                        Disable generalisation. Generalisation creates rules
                        with less specific matches. See
                        ofsolver.solver.valid_generalisation.
  -o {NO_CONFLICT,NO_HIT,NO_MISS,NO_PLACEMENT,NO_PLACEMENT_CONFLICT,NO_SAME_TABLE}, --option {NO_CONFLICT,NO_HIT,NO_MISS,NO_PLACEMENT,NO_PLACEMENT_CONFLICT,NO_SAME_TABLE}
                        Additional solver specific options
```

### Installing

Install the C library requirements for [gmpy2](https://gmpy2.readthedocs.io/en/latest/) as required by [ofequivalence](https://github.com/wandsdn/ofequivalence). For Debian based distributions run:
```
apt install libgmp-dev libmpfr-dev libmpc-dev
```
Install the python requirements. In the root directory (containing this readme) run:
```
pip install -r requirements.txt
```
Download the required [minisat-zmq](https://github.com/wandsdn/minisat-zmq) and [muser2](https://bitbucket.org/anton_belov/muser2/src/master/) binaries, these are placed locally in the ofsolver directory. Alternativelly see the documentation of those projects and install the binaries to the system path.
```
./setup.py download
```
Install the ofsolver tool and library (use the pip --user option to install for only the local user):
```
pip install .
```

### Running tests

Note: tests require minisat to be installed to the system path (on debian based systems ```apt install minisat2```).

Unittest is used to run tests.

In the root directory, the following command will run the tests locally:
```
./setup.py test
```
Or alternatively:
```
python -m unittest discover -v
```

### License

The code is licensed under the Apache License Version 2.0, see the included
LICENSE file.
