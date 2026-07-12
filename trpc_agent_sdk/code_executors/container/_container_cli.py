# -*- coding: utf-8 -*-
#
# Copyright @ 2025 Tencent.com
"""Container code executor for TRPC Agent framework.

This module provides a code executor that uses a custom container to execute code.
This executor provides better isolation and security compared to unsafe local execution.
"""

from __future__ import annotations

import asyncio
import atexit
import json
import os
import socket as pysocket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

import docker
from docker.models.containers import Container
from docker.utils.socket import demux_adaptor
from docker.utils.socket import frames_iter
from trpc_agent_sdk.log import logger

DEFAULT_IMAGE_TAG = 'python:3-slim'
_DEFAULT_STREAM_LIMIT_BYTES = 16 * 1024
_CONTROL_POLL_SECONDS = 0.01
# A control-file read is itself a Docker exec. Desktop/remote daemons can take
# longer than 200 ms to start that probe even though the supervisor is ready.
_CONTROL_READY_SECONDS = 2.0
_READER_GRACE_SECONDS = 1.0


@dataclass
class ContainerConfig:
    """Configuration for container."""
    base_url: Optional[str] = None
    """The base url of the user hosted Docker client."""
    image: str = DEFAULT_IMAGE_TAG
    """The tag of the predefined image or custom image to run on the container.
    Either docker_path or image must be set.
    """
    docker_path: Optional[str] = None
    """The path to the Docker file to build the image from."""
    host_config: Optional[dict] = None
    """Optional host config (for example {"Binds": ["/host:/container:ro"]})."""


@dataclass
class CommandArgs:
    """Command arguments."""
    environment: Optional[dict[str, str]] = None
    """The environment variables for the command execution."""
    timeout: Optional[float] = None
    """The timeout for the command execution in seconds."""
    stdin: Optional[str | bytes] = None
    """Optional stdin content to write once before reading output."""
    close_stdin: bool = True
    stdout_limit_bytes: int = 0
    stderr_limit_bytes: int = 0
    output_globs: tuple[str, ...] = ()
    output_limit_bytes: int = 0


@dataclass(frozen=True)
class ContainerExecResult:
    stdout: str
    stderr: str
    exit_code: int
    is_timeout: bool
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_bytes_observed: int = 0
    stderr_bytes_observed: int = 0
    execution_started: bool = False
    failure_kind: str = ""
    termination_confirmed: bool = True
    termination_reason: str = ""


@dataclass(frozen=True)
class _BoundedFramesResult:
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_bytes_observed: int
    stderr_bytes_observed: int


def _consume_bounded_frames(
    frames: Iterable[tuple[Optional[bytes], Optional[bytes]]],
    *,
    stdout_limit_bytes: int,
    stderr_limit_bytes: int,
    terminate: Callable[[], None],
) -> _BoundedFramesResult:
    """Consume demuxed Docker frames without retaining unbounded output."""
    captures = [bytearray(), bytearray()]
    observed = [0, 0]
    truncated = [False, False]
    terminated = False
    limits = [max(0, stdout_limit_bytes), max(0, stderr_limit_bytes)]
    for frame in frames:
        for index, chunk in enumerate(frame):
            if not chunk:
                continue
            observed[index] += len(chunk)
            remaining = max(0, limits[index] - len(captures[index]))
            captures[index].extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated[index] = True
                if not terminated:
                    terminated = True
                    terminate()
        if terminated:
            break
    return _BoundedFramesResult(bytes(captures[0]), bytes(captures[1]), truncated[0], truncated[1], observed[0],
                                observed[1])


def _decode_bounded(data: bytes, limit_bytes: int) -> str:
    """Decode replacement-safe text without expanding past its byte budget."""
    decoded = data.decode("utf-8", errors="replace")
    remaining = max(0, limit_bytes)
    retained: list[str] = []
    for char in decoded:
        encoded = char.encode("utf-8")
        if len(encoded) > remaining:
            break
        retained.append(char)
        remaining -= len(encoded)
    return "".join(retained)


class ContainerClient:
    """Container CLI client class."""

    def __init__(self, config: ContainerConfig):
        """Initialize the container."""
        self.base_url = config.base_url
        self.image = config.image
        self.docker_path = os.path.abspath(config.docker_path) if config.docker_path else None
        self.host_config = config.host_config or {}
        self._client = None
        self._container = None
        self._closed = False
        self._init_docker_client()
        try:
            self._init_container()
        except BaseException:
            try:
                self.close()
            except Exception:  # pylint: disable=broad-except
                logger.exception("Failed to clean a partially initialized container")
            raise
        atexit.register(self._cleanup_container)

    @property
    def client(self) -> docker.DockerClient:
        """Get the Docker client."""
        return self._client

    @property
    def container(self) -> Container:
        """Get the container."""
        return self._container

    def _init_docker_client(self):
        """Initialize the Docker client with comprehensive error handling.

        This method attempts to connect to Docker using docker SDK's from_env()
        which handles various Docker connection methods including:
        - Standard Unix socket (/var/run/docker.sock)
        - Docker Desktop (Windows/Mac)
        - Remote Docker via DOCKER_HOST environment variable
        - Custom base_url if provided
        """
        # Try to initialize Docker client
        # Let docker SDK handle connection detection (it supports various methods)
        try:
            if self.base_url:
                # Use custom base_url if provided
                self._client = docker.DockerClient(base_url=self.base_url)
            else:
                # Use docker.from_env() which automatically detects:
                # - DOCKER_HOST environment variable
                # - Standard socket paths
                # - Docker Desktop configurations
                self._client = docker.from_env()

            # Test connection by pinging Docker daemon
            # This will fail if Docker is not running or not accessible
            self._client.ping()
            logger.info("Docker client initialized successfully")
        except docker.errors.DockerException as ex:
            # Extract more specific error information
            error_str = str(ex)

            # Check if it's a connection error
            if "Connection" in error_str or "socket" in error_str.lower() or "No such file" in error_str:
                error_msg = ("Failed to connect to Docker daemon. Docker may not be running or accessible.\n\n"
                             "Common solutions:\n"
                             "  1. Start Docker daemon:\n"
                             "     - Linux: sudo systemctl start docker\n"
                             "     - Windows/Mac: Start Docker Desktop application\n"
                             "  2. Verify Docker is running: docker ps\n"
                             "  3. Check Docker socket permissions (Linux):\n"
                             "     - sudo chmod 666 /var/run/docker.sock\n"
                             "     - Or add your user to docker group: sudo usermod -aG docker $USER\n"
                             "  4. For Docker Desktop, ensure it's fully started (check system tray)\n"
                             "  5. Check DOCKER_HOST environment variable if using remote Docker\n"
                             "  6. If using remote Docker, set base_url parameter in ContainerCodeExecutor\n\n"
                             f"Original error: {error_str}")
            else:
                error_msg = (f"Failed to connect to Docker daemon: {error_str}\n\n"
                             "Please ensure:\n"
                             "  1. Docker daemon is running: docker ps\n"
                             "  2. You have permission to access Docker\n"
                             "  3. Docker is properly installed and configured")
            raise RuntimeError(error_msg) from ex
        except Exception as ex:  # pylint: disable=broad-except
            error_msg = (f"Unexpected error initializing Docker client: {str(ex)}\n\n"
                         "Please check:\n"
                         "  1. Docker installation: docker --version\n"
                         "  2. Docker daemon status: docker ps\n"
                         "  3. Docker SDK installation: pip show docker")
            raise RuntimeError(error_msg) from ex

    def _init_container(self):
        """Initialize the container."""
        if not self._client:
            raise RuntimeError("Docker client is not initialized.")

        if self.docker_path:
            self._build_docker_image()

        logger.info("Starting container for ContainerCodeExecutor...")
        run_kwargs = {}
        binds = self.host_config.get("Binds")
        if binds:
            # docker SDK `run` supports bind specs via `volumes`.
            run_kwargs["volumes"] = binds
            logger.info("Container bind mounts enabled: %s", binds)
        command = self.host_config.get("command", ["tail", "-f", "/dev/null"])
        stdin = self.host_config.get("stdin", True)
        working_dir = self.host_config.get("working_dir", "/")
        network_mode = self.host_config.get("network_mode", "none")
        auto_remove = self.host_config.get("auto_remove", True)
        self._auto_remove = bool(auto_remove)
        for key in (
                "mem_limit",
                "memswap_limit",
                "nano_cpus",
                "pids_limit",
                "read_only",
                "tmpfs",
                "shm_size",
        ):
            if key in self.host_config:
                run_kwargs[key] = self.host_config[key]
        run_kwargs.setdefault("command", command)
        run_kwargs.setdefault("stdin_open", stdin)
        run_kwargs.setdefault("working_dir", working_dir)
        run_kwargs.setdefault("network_mode", network_mode)
        run_kwargs.setdefault("auto_remove", auto_remove)
        if self.host_config.get("init"):
            run_kwargs.setdefault("init", True)
        self._container = self._client.containers.run(
            image=self.image,
            detach=True,
            tty=True,
            **run_kwargs,
        )
        logger.info("Container %s started.", self._container.id)

        # Verify the container is able to run python3.
        self._verify_python_installation()

    def _build_docker_image(self):
        """Build the Docker image."""
        if not self.docker_path:
            raise ValueError("Docker path is not set.")
        if not os.path.exists(self.docker_path):
            raise FileNotFoundError(f"Invalid Docker path: {self.docker_path}")

        logger.info("Building Docker image...")
        self._client.images.build(
            path=self.docker_path,
            tag=self.image,
            rm=True,
        )
        logger.info("Docker image: %s built.", self.image)

    def _verify_python_installation(self):
        """Verify the container has python3 installed."""
        exec_result = self._container.exec_run(["which", "python3"])
        if exec_result.exit_code != 0:
            raise ValueError("python3 is not installed in the container.")

    def _cleanup_container(self):
        """Close the container on exit."""
        self.close()

    def close(self):
        """Stop and remove the owned container exactly once."""
        if getattr(self, "_closed", False):
            return
        if not self._container:
            self._closed = True
            try:
                atexit.unregister(self._cleanup_container)
            except Exception:  # pylint: disable=broad-except
                pass
            return
        container = self._container
        logger.info("[Cleanup] Stopping the container...")
        failures = []
        try:
            container.stop()
        except docker.errors.NotFound:
            pass
        except Exception as exc:  # pylint: disable=broad-except
            failures.append(exc)
        if not getattr(self, "_auto_remove", False):
            try:
                container.remove()
            except docker.errors.NotFound:
                pass
            except Exception as exc:  # pylint: disable=broad-except
                failures.append(exc)
        if failures:
            raise RuntimeError(f"container cleanup failed: {failures[0]}") from failures[0]
        self._container = None
        self._closed = True
        try:
            atexit.unregister(self._cleanup_container)
        except Exception:  # pylint: disable=broad-except
            pass
        logger.info("Container %s stopped and removed.", container.id)

    @staticmethod
    def _supervised_command(cmd: list[str], args: CommandArgs, token: str) -> tuple[list[str], str, str]:
        pid_file = f"/tmp/trpc-exec-{token}.pid"
        reason_file = f"/tmp/trpc-exec-{token}.reason"
        payload = json.dumps({
            "cmd": cmd,
            "pid": pid_file,
            "reason": reason_file,
            "globs": list(args.output_globs),
            "limit": args.output_limit_bytes
        })
        script = (
            "import glob,json,os,signal,stat,subprocess,sys,threading,time\n"
            "p=json.loads(sys.argv[1]); stop=threading.Event(); reason=['']; high=[0]\n"
            "c=subprocess.Popen(p['cmd'],start_new_session=True)\n"
            "open(p['pid'],'w').write(str(c.pid))\n"
            "def write_reason(value):\n"
            " if reason[0]=='orchestration_error': return\n"
            " if value=='orchestration_error' or not reason[0]: reason[0]=value; open(p['reason'],'w').write(value)\n"
            "def total():\n"
            " files=set()\n"
            " for pat in p['globs']:\n"
            "  files.update(os.path.realpath(f) for f in glob.glob(pat,recursive=True))\n"
            " size=0\n"
            " for f in files:\n"
            "  info=os.stat(f)\n"
            "  if stat.S_ISDIR(info.st_mode): continue\n"
            "  if not stat.S_ISREG(info.st_mode): raise OSError('non-regular output')\n"
            "  size+=info.st_size\n"
            " high[0]=max(high[0],size); return size\n"
            "def absent():\n"
            " for _ in range(50):\n"
            "  live=False\n"
            "  for path in glob.glob('/proc/[0-9]*/stat'):\n"
            "   try:\n"
            "    fields=open(path).read().rsplit(')',1)[1].split()\n"
            "    if int(fields[2])==c.pid and fields[0]!='Z': live=True; break\n"
            "   except (OSError,ValueError,IndexError): pass\n"
            "  if not live: return True\n"
            "  time.sleep(.01)\n"
            " return False\n"
            "def kill(value):\n"
            " write_reason(value)\n"
            " try: os.killpg(c.pid,signal.SIGKILL)\n"
            " except ProcessLookupError: pass\n"
            " if not absent(): write_reason('orchestration_error')\n"
            "def watch():\n"
            " try:\n"
            "  while not stop.wait(.02):\n"
            "   if p['limit'] and total()>p['limit']: kill('output_limit_exceeded'); return\n"
            " except BaseException: kill('orchestration_error')\n"
            "t=threading.Thread(target=watch); t.start(); rc=c.wait(); stop.set(); t.join()\n"
            "try:\n"
            " final=total()\n"
            "except BaseException:\n"
            " kill('orchestration_error'); rc=125\n"
            "else:\n"
            " if p['limit'] and max(final,high[0])>p['limit']: kill('output_limit_exceeded'); rc=137\n"
            " if not absent(): kill('orchestration_error'); rc=125\n"
            "if reason[0] and rc==0: rc=125\n"
            "sys.exit(rc)\n")
        return ["python3", "-c", script, payload], pid_file, reason_file

    def _terminate_exec_group(self, pid_file: str) -> bool:
        if not pid_file:
            return False
        script = ("import glob,os,signal,sys,time\n"
                  "try: p=int(open(sys.argv[1]).read())\n"
                  "except (FileNotFoundError,ValueError): sys.exit(1)\n"
                  "if p<=0: sys.exit(1)\n"
                  "try: os.killpg(p,signal.SIGKILL)\n"
                  "except ProcessLookupError: sys.exit(0)\n"
                  "for _ in range(200):\n"
                  " live=False\n"
                  " for path in glob.glob('/proc/[0-9]*/stat'):\n"
                  "  try:\n"
                  "   fields=open(path).read().rsplit(')',1)[1].split()\n"
                  "   if int(fields[2])==p and fields[0]!='Z': live=True; break\n"
                  "  except (OSError,ValueError,IndexError): pass\n"
                  " if not live: sys.exit(0)\n"
                  " time.sleep(.01)\n"
                  "sys.exit(2)")
        try:
            return self.container.exec_run(["python3", "-c", script, pid_file]).exit_code == 0
        except Exception:  # pylint: disable=broad-except
            return False

    def _read_control_file(self, path: str) -> str:
        if not path:
            return ""
        try:
            result = self.container.exec_run(["cat", path])
            if result.exit_code == 0:
                output = result.output
                if isinstance(output, tuple):
                    output = output[0]
                if isinstance(output, bytes):
                    return output.decode("utf-8", errors="replace").strip()
                return str(output or "").strip()
        except Exception:  # pylint: disable=broad-except
            pass
        return ""

    def _exec_group_absent(self, pid_file: str) -> bool:
        if not pid_file:
            return False
        script = ("import glob,os,sys\n"
                  "try: p=int(open(sys.argv[1]).read())\n"
                  "except (FileNotFoundError,ValueError): sys.exit(1)\n"
                  "if p<=0: sys.exit(1)\n"
                  "for path in glob.glob('/proc/[0-9]*/stat'):\n"
                  " try:\n"
                  "  fields=open(path).read().rsplit(')',1)[1].split()\n"
                  "  if int(fields[2])==p and fields[0]!='Z': sys.exit(1)\n"
                  " except (OSError,ValueError,IndexError): pass\n"
                  "sys.exit(0)")
        try:
            return self.container.exec_run(["python3", "-c", script, pid_file]).exit_code == 0
        except Exception:  # pylint: disable=broad-except
            return False

    def _wait_for_ready(self, pid_file: str) -> bool:
        deadline = time.monotonic() + _CONTROL_READY_SECONDS
        while True:
            raw = self._read_control_file(pid_file)
            try:
                if int(raw) > 0:
                    return True
            except (TypeError, ValueError):
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(_CONTROL_POLL_SECONDS)

    def _exec_stopped(self, exec_id: str) -> bool:
        if not exec_id:
            return False
        try:
            return not bool(self.container.client.api.exec_inspect(exec_id).get("Running"))
        except Exception:  # pylint: disable=broad-except
            return False

    def _wait_exec_stopped(self, exec_id: str, *, timeout: float = _READER_GRACE_SECONDS) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            if self._exec_stopped(exec_id):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_CONTROL_POLL_SECONDS)

    def _kill_container(self) -> bool:
        try:
            self.container.kill()
            self.container.reload()
            return self.container.status != "running"
        except Exception:  # pylint: disable=broad-except
            return False

    @staticmethod
    def _close_exec_socket(sock) -> None:
        if sock is None:
            return
        candidates = [sock]
        inner = getattr(sock, "_sock", None)
        if inner is not None and inner is not sock:
            candidates.append(inner)
        for candidate in candidates:
            try:
                candidate.shutdown(pysocket.SHUT_RDWR)
            except Exception:  # pylint: disable=broad-except
                pass
            try:
                candidate.close()
            except Exception:  # pylint: disable=broad-except
                pass

    def _stream_exec(self, cmd: list[str], args: CommandArgs, state: dict) -> ContainerExecResult:
        # Preserve lightweight injected Docker-model fakes used by downstream
        # callers; production clients always have the low-level client set.
        if not hasattr(self, "_client"):
            legacy = self.container.exec_run(cmd=cmd[:], demux=True, environment=args.environment or {})
            if hasattr(legacy, "stdout") and hasattr(legacy, "stderr"):
                return ContainerExecResult(
                    str(legacy.stdout or ""),
                    str(legacy.stderr or ""),
                    int(legacy.exit_code),
                    bool(getattr(legacy, "is_timeout", False)),
                    execution_started=True,
                    failure_kind="execution_nonzero" if legacy.exit_code else "",
                )
            exit_code = legacy.exit_code if hasattr(legacy, "exit_code") else legacy[0]
            output = legacy.output if hasattr(legacy, "output") else legacy[1]
            stdout = output[0] if output else None
            stderr = output[1] if output else None
            return ContainerExecResult((stdout or b"").decode("utf-8", errors="replace"),
                                       (stderr or b"").decode("utf-8", errors="replace"),
                                       int(exit_code),
                                       False,
                                       execution_started=True,
                                       failure_kind="execution_nonzero" if exit_code else "")
        for value in (args.stdout_limit_bytes, args.stderr_limit_bytes, args.output_limit_bytes):
            if type(value) is not int or value < 0:
                raise ValueError("container byte limits must be non-negative integers")
        if any(not isinstance(pattern, str) or not pattern.startswith("/") for pattern in args.output_globs):
            raise ValueError("container output globs must be absolute paths")
        stdout_limit = args.stdout_limit_bytes or _DEFAULT_STREAM_LIMIT_BYTES
        stderr_limit = args.stderr_limit_bytes or _DEFAULT_STREAM_LIMIT_BYTES
        supervised, pid_file, reason_file = self._supervised_command(cmd, args, uuid.uuid4().hex)
        sock = None
        writer = None
        writer_error: list[BaseException] = []
        try:
            resp = self.container.client.api.exec_create(self.container.id,
                                                         cmd=supervised,
                                                         stdout=True,
                                                         stderr=True,
                                                         stdin=args.stdin is not None,
                                                         tty=False,
                                                         environment=args.environment or {})
            exec_id = resp["Id"]
            state.update(exec_id=exec_id, pid_file=pid_file, reason_file=reason_file, exec_created=True)
            sock = self.container.client.api.exec_start(exec_id,
                                                        detach=False,
                                                        tty=False,
                                                        stream=False,
                                                        socket=True,
                                                        demux=False)
            state.update(socket=sock, low_level_started=True)
            state["ready"] = self._wait_for_ready(pid_file)
            if not state["ready"]:
                raise RuntimeError("container supervisor did not report a ready process group")

            def write_stdin():
                try:
                    raw_stdin = args.stdin or b""
                    data = raw_stdin if isinstance(raw_stdin, bytes) else raw_stdin.encode("utf-8")
                    if data:
                        sendall = getattr(sock, "sendall", None)
                        if not callable(sendall):
                            sendall = sock._sock.sendall  # pylint: disable=protected-access
                        sendall(data)
                    if args.close_stdin:
                        try:
                            sock.shutdown(pysocket.SHUT_WR)
                        except Exception:  # pylint: disable=broad-except
                            close_write = getattr(sock, "close_write", None)
                            if callable(close_write):
                                close_write()
                except BaseException as exc:  # pylint: disable=broad-except
                    writer_error.append(exc)
                    if not self._terminate_exec_group(pid_file):
                        state["container_killed"] = self._kill_container()
                    self._close_exec_socket(sock)

            if args.stdin is not None:
                writer = threading.Thread(target=write_stdin, name=f"container-stdin-{exec_id}")
                writer.start()
            overflow = False

            def terminate():
                nonlocal overflow
                overflow = True
                if not self._terminate_exec_group(pid_file):
                    state["container_killed"] = self._kill_container()

            demuxed = (demux_adaptor(*frame) for frame in frames_iter(sock, tty=False))
            captured = _consume_bounded_frames(demuxed,
                                               stdout_limit_bytes=stdout_limit,
                                               stderr_limit_bytes=stderr_limit,
                                               terminate=terminate)
            if writer:
                writer.join(timeout=_READER_GRACE_SECONDS)
                if writer.is_alive():
                    if not self._terminate_exec_group(pid_file):
                        state["container_killed"] = self._kill_container()
                    self._close_exec_socket(sock)
                    writer.join(timeout=_READER_GRACE_SECONDS)
                if writer.is_alive():
                    raise RuntimeError("container stdin writer did not finish")
            if writer_error:
                raise RuntimeError(f"failed to write container stdin: {writer_error[0]}")
            self._wait_exec_stopped(exec_id)
            self._close_exec_socket(sock)
            inspect = self.container.client.api.exec_inspect(exec_id)
            running = bool(inspect.get("Running"))
            reason = self._read_control_file(reason_file)
            if reason not in {"", "output_limit_exceeded", "orchestration_error"}:
                reason = "orchestration_error"
            if overflow and reason != "orchestration_error":
                reason = "output_limit_exceeded"
            if running:
                reason = "orchestration_error"
                if not self._terminate_exec_group(pid_file):
                    state["container_killed"] = self._kill_container()
                running = not (state.get("container_killed") or self._wait_exec_stopped(exec_id))
            exit_code = int(inspect.get("ExitCode", -1))
            if reason and exit_code == 0:
                exit_code = -1
            failure_kind = reason or ("execution_nonzero" if exit_code != 0 else "")
            group_absent = bool(state.get("container_killed")) or self._exec_group_absent(pid_file)
            confirmed = not running and group_absent
            if not confirmed:
                container_killed = self._kill_container()
                state["container_killed"] = container_killed
                confirmed = container_killed
                failure_kind = "orchestration_error"
                reason = "orchestration_error"
                if exit_code == 0:
                    exit_code = -1
            return ContainerExecResult(
                _decode_bounded(captured.stdout, stdout_limit),
                _decode_bounded(captured.stderr, stderr_limit),
                exit_code,
                False,
                captured.stdout_truncated,
                captured.stderr_truncated,
                captured.stdout_bytes_observed,
                captured.stderr_bytes_observed,
                bool(state.get("ready")),
                failure_kind,
                confirmed,
                reason,
            )
        except BaseException:
            if state.get("low_level_started"):
                confirmed = self._terminate_exec_group(pid_file)
                if not confirmed:
                    confirmed = self._kill_container()
                state["cleanup_confirmed"] = confirmed
            self._close_exec_socket(sock)
            if writer is not None:
                writer.join(timeout=_READER_GRACE_SECONDS)
                if writer.is_alive():
                    state["container_killed"] = self._kill_container()
                    self._close_exec_socket(sock)
                    writer.join()
            raise

    async def exec_run(self, cmd: list[str], command_args: CommandArgs) -> ContainerExecResult:
        """Execute command in container."""
        timeout = command_args.timeout
        state: dict = {}
        future = None
        timer = None
        try:
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(None, lambda: self._stream_exec(cmd, command_args, state))
            if timeout is None:
                return await asyncio.shield(future)
            timer = asyncio.create_task(asyncio.sleep(max(0.0, float(timeout))))
            done, _ = await asyncio.wait({future, timer}, return_when=asyncio.FIRST_COMPLETED)
            if future in done:
                timer.cancel()
                return future.result()

            confirmed = self._terminate_exec_group(state.get("pid_file", ""))
            if not confirmed:
                confirmed = self._kill_container()
                state["container_killed"] = confirmed
            self._close_exec_socket(state.get("socket"))
            try:
                result = await asyncio.wait_for(asyncio.shield(future), timeout=_READER_GRACE_SECONDS)
            except asyncio.TimeoutError:
                container_killed = self._kill_container()
                state["container_killed"] = container_killed
                confirmed = container_killed or confirmed
                self._close_exec_socket(state.get("socket"))
                result = await asyncio.shield(future)
            except Exception:  # pylint: disable=broad-except
                result = None
            stopped = bool(state.get("container_killed")) or self._wait_exec_stopped(state.get("exec_id", ""))
            confirmed = confirmed and stopped
            observed_reason = result.failure_kind if result is not None else ""
            if not observed_reason and not state.get("container_killed"):
                observed_reason = self._read_control_file(state.get("reason_file", ""))
            if observed_reason not in {"", "output_limit_exceeded", "orchestration_error"}:
                observed_reason = "orchestration_error"
            failure = "execution_timeout" if confirmed else "orchestration_error"
            if observed_reason == "output_limit_exceeded" and confirmed:
                return ContainerExecResult(
                    result.stdout if result is not None else "",
                    result.stderr if result is not None else "",
                    -1,
                    False,
                    stdout_truncated=result.stdout_truncated if result is not None else False,
                    stderr_truncated=result.stderr_truncated if result is not None else False,
                    stdout_bytes_observed=result.stdout_bytes_observed if result is not None else 0,
                    stderr_bytes_observed=result.stderr_bytes_observed if result is not None else 0,
                    execution_started=bool(state.get("ready")) or bool(result is not None and result.execution_started),
                    failure_kind="output_limit_exceeded",
                    termination_confirmed=True,
                    termination_reason="output_limit_exceeded",
                )
            timeout_message = f"Command timed out after {timeout}s in `{' '.join(cmd)}`\n"
            return ContainerExecResult(result.stdout if result is not None else "",
                                       result.stderr if result is not None and result.stderr else timeout_message,
                                       -1,
                                       True,
                                       stdout_truncated=result.stdout_truncated if result is not None else False,
                                       stderr_truncated=result.stderr_truncated if result is not None else False,
                                       stdout_bytes_observed=result.stdout_bytes_observed if result is not None else 0,
                                       stderr_bytes_observed=result.stderr_bytes_observed if result is not None else 0,
                                       execution_started=bool(state.get("ready"))
                                       or bool(result is not None and result.execution_started),
                                       failure_kind=failure,
                                       termination_confirmed=confirmed,
                                       termination_reason=failure)
        except asyncio.CancelledError:
            confirmed = self._terminate_exec_group(state.get("pid_file", ""))
            if not confirmed:
                confirmed = self._kill_container()
                state["container_killed"] = confirmed
            self._close_exec_socket(state.get("socket"))
            if future is not None:
                try:
                    await asyncio.shield(future)
                except Exception:  # pylint: disable=broad-except
                    pass
            raise
        except Exception as ex:  # pylint: disable=broad-except
            started = bool(state.get("ready"))
            low_level_started = bool(state.get("low_level_started"))
            confirmed = bool(state.get("cleanup_confirmed")) if low_level_started else False
            return ContainerExecResult(
                stdout="",
                stderr=f"Execution error: {str(ex)} in `{' '.join(cmd)}`\n",
                exit_code=-1,
                is_timeout=False,
                execution_started=started,
                failure_kind="orchestration_error" if low_level_started else "runtime_unavailable",
                termination_confirmed=confirmed,
                termination_reason="orchestration_error" if low_level_started else "")
        finally:
            if timer is not None and not timer.done():
                timer.cancel()
