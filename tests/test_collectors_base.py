"""Tests for the collection engine base classes."""

from __future__ import annotations

from mijhar.collectors.base import CommandRunner, Fact
from tests.conftest import FakeRunner, result


def test_command_result_ok_and_output():
    r = result(0, stdout="  hello\n")
    assert r.ok is True
    assert r.output == "hello"


def test_command_result_error():
    r = result(2, stderr="boom")
    assert r.ok is False
    assert r.error == "boom"


def test_fake_runner_records_calls_and_returns_default():
    runner = FakeRunner({("echo", "x"): result(0, "x")})
    assert runner.run(["echo", "x"]).output == "x"
    assert runner.run(["missing"]).returncode == 1
    assert runner.called(["echo", "x"])


def test_fact_as_dict_roundtrip():
    f = Fact(key="a.b", value=True, source="cmd --flag", raw="1", error=None)
    d = f.as_dict()
    assert d["key"] == "a.b"
    assert d["value"] is True
    assert d["raw"] == "1"
    assert d["error"] is None


def test_command_runner_missing_binary():
    runner = CommandRunner()
    out = runner.run(["/definitely/not/a/real/binary", "arg"])
    assert out.returncode == 127
    assert not out.ok
    assert "not found" in out.stderr
