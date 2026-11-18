"""Regression P14: a streamed tool that forks pipe-inheriting children must
still honour its deadline.

Live finding: crawl had a 2700s ceiling; katana was killed at the deadline but
the stage stayed "running" because katana -jc spawns chrome, chrome inherited
the stdout pipe, and "for line in proc.stdout" waits for EOF -- which never
arrived.

Second live finding (attempt 7 of the same run): the ceiling was 2700s and the
stage was still "running" at 3169s. The child had gone silent -- no lines at
all -- so the read loop's deadline was never reached: it only checked the clock
after a line arrived, and a readline() already blocked in the calling thread
cannot be interrupted. run_stream now reads on a daemon helper and joins it
with the deadline, so expiry is enforced whether the child is chatty, silent,
or gone-but-not-reaped.
"""
import sys
import time

import tests.util  # noqa: F401
from tests.util import fresh_core


def test_run_stream_stops_at_deadline_even_if_pipe_stays_open():
    core = fresh_core()
    code = chr(10).join([
        "import subprocess, sys, time",
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])",
        "for i in range(3):",
        "    print('line-%d' % i, flush=True)",
        "time.sleep(60)",
    ])
    seen = []
    t0 = time.time()
    rc, lines, _err = core.run_stream([sys.executable, "-c", code],
                                      lambda ln: seen.append(ln), timeout=2)
    elapsed = time.time() - t0
    assert elapsed < 20, "run_stream ignored its deadline: %.1fs" % elapsed
    assert rc == 124, "a timed-out stream must report 124, got %r" % (rc,)
    assert seen, "lines emitted before the deadline must be kept"


def test_run_stream_normal_completion_is_unaffected():
    core = fresh_core()
    seen = []
    rc, lines, _err = core.run_stream(
        [sys.executable, "-c", "print(1); print(2)"],
        lambda ln: seen.append(ln), timeout=30)
    assert rc == 0, rc
    assert seen == ["1", "2"], seen


def test_run_stream_deadline_fires_on_a_silent_child():
    """No output at all: the worst case, the read loop never wakes up."""
    core = fresh_core()
    seen = []
    t0 = time.time()
    rc, lines, _err = core.run_stream(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        lambda ln: seen.append(ln), timeout=2)
    elapsed = time.time() - t0
    assert rc == 124, "a silent timed-out stream must report 124, got %r" % (rc,)
    assert elapsed < 20, "silent child ignored its deadline: %.1fs" % elapsed
    assert not seen


def test_run_stream_deadline_stops_a_silent_child_that_holds_the_pipe():
    """Child silent AND a grandchild holds stdout open -- the live shape."""
    core = fresh_core()
    code = chr(10).join([
        'import subprocess, sys, time',
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])",
        "print('only-line', flush=True)",
        'time.sleep(120)',
    ])
    seen = []
    t0 = time.time()
    rc, _lines, _err = core.run_stream([sys.executable, '-c', code],
                                       lambda ln: seen.append(ln), timeout=2)
    elapsed = time.time() - t0
    assert rc == 124, rc
    assert elapsed < 25, "stream with pipe-holding grandchild ignored deadline: %.1fs" % elapsed
    assert seen == ["only-line"], seen
