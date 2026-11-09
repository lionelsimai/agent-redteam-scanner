"""Adapters so the scanner can fuzz *your own* agent, not just the mocks.

Two ways to plug in a real agent:

- ``--agent-command "python my_agent.py"`` — the scanner spawns the
  command once and speaks a line protocol: one prompt per line on
  stdin, one response line per prompt on stdout.
- ``--agent-module path/to/module.py:ClassName`` (or
  ``package.module:ClassName``) — the class is instantiated with no
  arguments and must provide ``respond(prompt) -> str``.
"""
from __future__ import annotations

import importlib
import importlib.util
import shlex
import subprocess
import sys
from pathlib import Path

from agent_redteam_scanner.agents import BaseAgent
from agent_redteam_scanner.errors import ScannerError


class AgentAdapterError(ScannerError):
    """Raised when a custom agent cannot be loaded or reached."""


class CommandAgent(BaseAgent):
    """An agent behind a subprocess speaking the line protocol."""

    def __init__(self, command: str, timeout: float = 30.0) -> None:
        """Spawn ``command`` and keep it alive for the whole scan."""
        self.name = f"command:{command}"
        self._timeout = timeout
        try:
            self._proc = subprocess.Popen(
                shlex.split(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except OSError as exc:
            raise AgentAdapterError(f"cannot start agent command {command!r}: {exc}") from exc

    def respond(self, prompt: str) -> str:
        """Send one prompt line, read one response line."""
        proc = self._proc
        if proc.stdin is None or proc.stdout is None or proc.poll() is not None:
            raise AgentAdapterError(f"agent process {self.name} is not running")
        try:
            proc.stdin.write(prompt.replace("\n", " ") + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
        except (OSError, ValueError) as exc:
            raise AgentAdapterError(f"agent process {self.name} failed: {exc}") from exc
        if line == "":
            raise AgentAdapterError(f"agent process {self.name} closed stdout (crashed?)")
        return line.rstrip("\n")

    def close(self) -> None:
        """Terminate the agent process."""
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()


def load_module_agent(spec: str) -> BaseAgent:
    """Load an agent class from ``module_or_path:ClassName``."""
    if ":" not in spec:
        raise AgentAdapterError(f"agent module spec must be 'module:Class', got {spec!r}")
    module_part, class_name = spec.rsplit(":", 1)
    try:
        if module_part.endswith(".py") or "/" in module_part:
            path = Path(module_part)
            if not path.exists():
                raise AgentAdapterError(f"agent module file not found: {module_part}")
            mod_spec = importlib.util.spec_from_file_location(path.stem, path)
            if mod_spec is None or mod_spec.loader is None:
                raise AgentAdapterError(f"cannot load agent module file: {module_part}")
            module = importlib.util.module_from_spec(mod_spec)
            sys.modules[path.stem] = module
            mod_spec.loader.exec_module(module)
        else:
            module = importlib.import_module(module_part)
        cls = getattr(module, class_name)
        agent = cls()
    except AgentAdapterError:
        raise
    except Exception as exc:
        raise AgentAdapterError(f"cannot load agent {spec!r}: {exc}") from exc
    if not callable(getattr(agent, "respond", None)):
        raise AgentAdapterError(f"{spec!r} has no callable respond(prompt) method")
    if not getattr(agent, "name", None):
        agent.name = f"module:{spec}"
    return agent  # type: ignore[return-value]
