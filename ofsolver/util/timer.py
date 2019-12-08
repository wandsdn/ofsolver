""" Convenience functions to time blocks of code

Time a block of code using the with statement:
    with timer.OneShotTimer("Block time") as time:
        # Some code
        pass
    print(time.get_time())

Measure subroutines as a percentage of a main routine:
class A:
    def __init__(self):
        self.timers = timer.TimerHierarchy('root')

    @timer.time_func('some_method')
    def some_method(self):
        self.nested_method()

    @timer.time_func('nested_method')
    def nested_method(self):
        pass
a = A()
a.some_method()
print(a.timers)
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

import timeit
from collections import OrderedDict

_TIMER_NEW = 0
_TIMER_RUNNING = 1
_TIMER_STOPPED = 2


class AbstractTimer(object):
    desc = None
    _tstart = None
    _state = _TIMER_NEW
    timer = timeit.default_timer
    _time = 0
    _hierarchy_root = None
    _children = None  # Map name -> Timer

    def __init__(self, desc, hierarchy_root=None):
        """ desc: A description or name for this timer """
        self.desc = desc
        if hierarchy_root is not None:
            self._hierarchy_root = hierarchy_root
            self._children = OrderedDict()

    def valid(self):
        """ Returns True if the Timer is in a valid state to be read.
            Otherwise, False, which indicates the timer was never started
            or is still running.
        """
        return self._state is _TIMER_STOPPED

    def running(self):
        """ Returns True if the Timer is running """
        return self._state is _TIMER_RUNNING

    def get_time(self):
        """ Returns the time on the timer """
        assert self.valid()
        return self._time

    def __enter__(self):
        """ Enter timer context

            I.e. for use with 'with'
            with timer:
                time this
            print(timer.get_time())
        """
        self.start()
        return self

    def __exit__(self, type_, value, traceback):
        """ Exit timer context """
        self.stop()

    def _start(self):
        """ Start the timer and change state

            Changes state to running and saves time in _tstart
        """
        self._state = _TIMER_RUNNING
        self._tstart = self.timer()
        if self._hierarchy_root is not None:
            self._hierarchy_root.timer_started(self)

    def start(self):
        """ Override with sanity checking logic

            If happy, call _start to start the timer
        """
        raise NotImplementedError()

    def _stop(self):
        """ Stop the timer and record the time

            Adds the time between _start() and _stop() to self._time
            This includes the state change logic
        """
        self._time += self.timer() - self._tstart
        self._state = _TIMER_STOPPED
        if self._hierarchy_root is not None:
            self._hierarchy_root.timer_stopped(self)

    def stop(self):
        """ Override with sanity checking logic

            If happy, call _stop to stop the timer
        """
        raise NotImplementedError()

    def __str__(self):
        return "{}: {:.6f}s".format(self.desc, self.get_time())

    def _str_rec(self, indent, absolute_perc=None, relative_perc=None):
        total = absolute_perc if absolute_perc is not None else relative_perc
        if total is not None and total is not True:
            ret = [indent + str(self) + " ({:.0f}%)".format(self.get_time()/total*100.0)]
        else:
            ret = [indent + str(self)]

        if self._children is not None:
            for child in self._children.values():
                if absolute_perc is not None:
                    if absolute_perc is True:
                        ret += child._str_rec(indent=indent+"  ", absolute_perc=self.get_time())
                    else:
                        ret += child._str_rec(indent=indent+"  ", absolute_perc=absolute_perc)
                elif relative_perc is not None:
                    ret += child._str_rec(indent=indent+"  ", relative_perc=self.get_time())
                else:
                    ret += child._str_rec(indent=indent+"  ")
        return ret


class OneShotTimer(AbstractTimer):
    """ A OneShotTimer

        Call start once, and stop once.
        Asserts if anything is bad.
    """
    def start(self):
        assert self._state is _TIMER_NEW
        self._start()

    def stop(self):
        assert self._state is _TIMER_RUNNING
        assert self._time is 0
        self._stop()


class ReentrantTimer(AbstractTimer):
    """ A Reentrant Timer

        Every call to start should be matched
        with a call to stop.
    """
    _entries = 0
    def start(self):
        if self._state == _TIMER_NEW:
            assert self._entries is 0
            assert self._tstart is None
            self._start()
        else:
            assert self._state == _TIMER_RUNNING
            self._entries += 1

    def stop(self):
        assert self._state is _TIMER_RUNNING
        assert self._entries > 0
        self._entries -= 1
        if self._entries == 0:
            self._stop()


class CumulativeTimer(AbstractTimer):
    """ A Cumulative Timer

        Where the combination of start and stop times are added together to
        form the total time.
        Every call to start, should be followed by a call to stop.
    """

    def valid(self):
        return self._state is _TIMER_STOPPED or self._state is _TIMER_NEW

    def start(self):
        assert self._state is _TIMER_STOPPED or self._state is _TIMER_NEW
        self._start()

    def stop(self):
        assert self._state is _TIMER_RUNNING
        self._stop()

class TimerHierarchy(object):
    """ Maintains a hierarchy of named timers """
    timer_class = None
    _running_timers = None
    _base_timer = None

    def __init__(self, base_desc, timer_class=CumulativeTimer):
        self.timer_class = timer_class
        self._base_timer = OneShotTimer(base_desc, hierarchy_root=self)
        self._running_timers = [self._base_timer]

    def timer(self, desc, timer_class=None):
        """ Return a timer at the current point in the hierarchy

            desc: The description of the timer created
            timer_class: The class of timer to use
        """
        if timer_class is None:
            timer_class = self.timer_class
        # Do we need to attach the base timer?
        if not self._running_timers:
            assert self._base_timer is None
            self._base_timer = timer_class(desc, hierarchy_root=self)
            return self._base_timer
        # Is this the current running timer?
        if desc == self._running_timers[-1].desc:
            return self._running_timers[-1]
        if desc not in self._running_timers[-1]._children:
            self._running_timers[-1]._children[desc] = timer_class(desc, hierarchy_root=self)
        return self._running_timers[-1]._children[desc]

    __call__ = timer

    def timer_started(self, timer):
        """ Called by a registered timer when it is started """
        if timer is not self._base_timer:
            assert timer.desc in self._running_timers[-1]._children
            self._running_timers.append(timer)
        else:
            assert self._running_timers[-1] is self._base_timer

    def timer_stopped(self, timer):
        """ Called by a registered timer when it is stopped """
        if timer is not self._base_timer:
            assert timer == self._running_timers[-1]
        self._running_timers.pop()

    def get_base(self):
        """ Get the base timer, the base timer should either be started
            and stopped once or never run.
        """
        return self._base_timer

    def __str__(self):
        assert len(self._running_timers) <= 1
        # Base timer not run
        if self._base_timer._state == _TIMER_NEW:
            assert self._running_timers[-1] == self._base_timer
            ret = []
            for child in self._base_timer._children.values():
                ret += child._str_rec(indent="", absolute_perc=child.get_time())
            return "\n".join(ret)

        # Otherwise default
        assert not self._running_timers
        ret = self._base_timer._str_rec(indent="", relative_perc=True)
        return "\n".join(ret)

def time_func(desc, timer_class=None):
    """ Annotation for timing a func

        Requires a TimerHierarchy on the instance at self.timers
    """
    def wrap(func):
        def _wrap(self, *args, **kwargs):
            with self.timers(desc, timer_class):
                return func(self, *args, **kwargs)
        return _wrap
    return wrap
