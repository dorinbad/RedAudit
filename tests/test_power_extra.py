#!/usr/bin/env python3
"""
Extra coverage for power helpers.
"""

from types import SimpleNamespace

from redaudit.core import power
from redaudit.core.power import SleepInhibitor, _XsetState


class _DummyRunner:
    def __init__(self, output=""):
        self.output = output
        self.calls = []

    def run(self, cmd, **_kwargs):
        self.calls.append(cmd)
        return SimpleNamespace(stdout=self.output, stderr="")


def test_capture_xset_state_parses_values(monkeypatch):
    output = (
        "Screen Saver:\n  timeout: 600    cycle: 600\n"
        "DPMS (Energy Star):\n  Standby: 300    Suspend: 600    Off: 900\n"
        "DPMS is Enabled\n"
    )
    runner = _DummyRunner(output)
    monkeypatch.setattr(power, "_make_runner", lambda **_kwargs: runner)

    inst = SleepInhibitor()
    state = inst._capture_xset_state("xset")

    assert state.screensaver_timeout == 600
    assert state.screensaver_cycle == 600
    assert state.dpms_standby == 300
    assert state.dpms_suspend == 600
    assert state.dpms_off == 900
    assert state.dpms_enabled is True
    assert state.screensaver_enabled is True


def test_restore_xset_state_invokes_commands(monkeypatch):
    runner = _DummyRunner()
    monkeypatch.setattr(power, "_make_runner", lambda **_kwargs: runner)

    inst = SleepInhibitor()
    state = _XsetState(
        screensaver_enabled=False,
        screensaver_timeout=0,
        screensaver_cycle=0,
        dpms_enabled=False,
        dpms_standby=10,
        dpms_suspend=20,
        dpms_off=30,
    )

    inst._restore_xset_state("xset", state)

    commands = [" ".join(cmd) for cmd in runner.calls]
    assert "xset s off" in commands
    assert "xset s 0 0" in commands
    assert "xset -dpms" in commands
    assert "xset dpms 10 20 30" in commands
