#!/usr/bin/env python3
"""ATHENA Benchmark Runner — XBOW-Compatible CTF Benchmark Orchestrator.

Orchestrates Docker containers for CTF benchmarks and feeds challenges
to ATHENA's multi-agent CTF mode. Compatible with the XBOW 104-challenge
validation benchmark format and any similarly structured benchmark.

Usage:
    # Run all challenges in a benchmark directory
    python benchmark_runner.py /path/to/benchmark-dir

    # Run specific challenges by name
    python benchmark_runner.py /path/to/benchmark-dir --challenges XBEN-001 XBEN-005

    # Run only difficulty 1 challenges (quick test)
    python benchmark_runner.py /path/to/benchmark-dir --difficulty 1

    # Custom timeout and ATHENA URL
    python benchmark_runner.py /path/to/benchmark-dir --timeout 1800 --athena-url http://localhost:8080

    # Dry run (list challenges without starting Docker)
    python benchmark_runner.py /path/to/benchmark-dir --dry-run

    # Resume from a previous run (skip already-solved challenges)
    python benchmark_runner.py /path/to/benchmark-dir --resume results-2026-03-01.json

XBOW Benchmark Format:
    benchmark-dir/
        benchmark.json          # Metadata: [{name, description, difficulty, tags, port}, ...]
        challenge-001/
            docker-compose.yml  # Docker app for this challenge
        challenge-002/
            docker-compose.yml
        ...

    Flag format: FLAG{<64-hex-chars>} (SHA-256 of benchmark name)
    Timeout: 30 minutes per challenge (configurable)

Leaderboard Reference:
    XBOW: 85.0% | Open-source best: 84.6% | MAPTA: 76.9%
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# ── Constants ─────────────────────────────────────────────────────

DEFAULT_ATHENA_URL = "http://localhost:8080"
DEFAULT_TIMEOUT_SEC = 1800  # 30 minutes per challenge (XBOW standard)
DEFAULT_ENGAGEMENT_ID = "eng-bench"
POLL_INTERVAL_SEC = 10  # Check scoreboard every 10 seconds
DOCKER_HEALTH_TIMEOUT_SEC = 60  # Wait up to 60s for container health
DOCKER_STARTUP_DELAY_SEC = 5  # Wait after compose up before health check
MAX_CONCURRENT_CHALLENGES = 5  # Run up to 5 challenges in parallel

# Known leaderboard scores for comparison
LEADERBOARD = {
    "XBOW": 85.0,
    "Open-source SOTA": 84.6,
    "MAPTA": 76.9,
    "Cyber-AutoAgent": 54.0,
    "PentestGPT": 28.0,
}

logger = logging.getLogger("athena-benchmark")


# ── Benchmark Loader ──────────────────────────────────────────────


def load_benchmark(bench_dir: Path) -> list[dict[str, Any]]:
    """Load benchmark.json and resolve per-challenge Docker paths.

    Supports two layouts:
    1. Single benchmark.json at root with challenge subdirs
    2. Per-challenge dirs with individual metadata files
    """
    bench_file = bench_dir / "benchmark.json"
    if not bench_file.exists():
        # Try alternate names
        for alt in ["challenges.json", "metadata.json", "benchmark.yaml"]:
            alt_path = bench_dir / alt
            if alt_path.exists():
                bench_file = alt_path
                break
        else:
            raise FileNotFoundError(
                f"No benchmark.json found in {bench_dir}. "
                "Expected XBOW format with benchmark.json at root."
            )

    data = json.loads(bench_file.read_text(encoding="utf-8"))
    challenges_raw = data if isinstance(data, list) else data.get("challenges", [])

    if not challenges_raw:
        raise ValueError(f"No challenges found in {bench_file}")

    challenges: list[dict[str, Any]] = []
    for i, ch in enumerate(challenges_raw):
        name = ch.get("name", f"challenge-{i + 1}")
        port = ch.get("port", 8000 + i)

        # Resolve Docker compose path
        compose_dir = _find_compose_dir(bench_dir, name, i)

        challenges.append({
            "name": name,
            "description": ch.get("description", ""),
            "difficulty": ch.get("difficulty", 1),
            "tags": ch.get("tags", []),
            "port": port,
            "points": ch.get("points", ch.get("difficulty", 1) * 100),
            "compose_dir": str(compose_dir) if compose_dir else None,
            "url": ch.get("url", f"http://localhost:{port}"),
        })

    return challenges


def _find_compose_dir(bench_dir: Path, name: str, index: int) -> Path | None:
    """Find the docker-compose directory for a challenge."""
    # Try exact name match
    for candidate in [
        bench_dir / name,
        bench_dir / name.lower(),
        bench_dir / name.replace(" ", "-").lower(),
        bench_dir / f"challenge-{index + 1:03d}",
        bench_dir / f"challenge-{index + 1}",
        bench_dir / f"ch{index + 1:03d}",
    ]:
        if candidate.is_dir():
            compose = candidate / "docker-compose.yml"
            if compose.exists():
                return candidate
            compose_alt = candidate / "docker-compose.yaml"
            if compose_alt.exists():
                return candidate

    # Scan subdirs for matching compose files
    for subdir in sorted(bench_dir.iterdir()):
        if subdir.is_dir() and name.lower() in subdir.name.lower():
            for compose_name in ["docker-compose.yml", "docker-compose.yaml"]:
                if (subdir / compose_name).exists():
                    return subdir

    return None


# ── Docker Orchestration ──────────────────────────────────────────


class DockerManager:
    """Manages Docker Compose lifecycle for benchmark challenges."""

    def __init__(self) -> None:
        self._active_containers: dict[str, Path] = {}  # name → compose_dir

    def start_challenge(self, name: str, compose_dir: Path, port: int) -> bool:
        """Start a challenge's Docker containers.

        Returns True if the container started and is reachable.
        """
        if not compose_dir or not compose_dir.exists():
            logger.warning("No compose dir for %s — skipping Docker", name)
            return True  # Assume externally managed

        logger.info("Starting Docker for %s (port %d)...", name, port)

        try:
            # Build and start
            subprocess.run(
                ["docker", "compose", "up", "-d", "--build"],
                cwd=str(compose_dir),
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error("Docker compose up failed for %s: %s", name, e.stderr[:500])
            return False
        except FileNotFoundError:
            logger.error("docker command not found — is Docker installed?")
            return False

        self._active_containers[name] = compose_dir

        # Wait for container to be reachable
        time.sleep(DOCKER_STARTUP_DELAY_SEC)
        return self._wait_for_health(f"http://localhost:{port}", name)

    def stop_challenge(self, name: str) -> None:
        """Stop a challenge's Docker containers."""
        compose_dir = self._active_containers.pop(name, None)
        if not compose_dir:
            return

        logger.info("Stopping Docker for %s...", name)
        try:
            subprocess.run(
                ["docker", "compose", "down", "--volumes", "--remove-orphans"],
                cwd=str(compose_dir),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except Exception as e:
            logger.warning("Failed to stop %s: %s", name, e)

    def stop_all(self) -> None:
        """Stop all active containers."""
        for name in list(self._active_containers.keys()):
            self.stop_challenge(name)

    @staticmethod
    def _wait_for_health(url: str, name: str) -> bool:
        """Wait for the challenge to respond to HTTP requests."""
        deadline = time.time() + DOCKER_HEALTH_TIMEOUT_SEC
        while time.time() < deadline:
            try:
                resp = httpx.get(url, timeout=5, follow_redirects=True)
                if resp.status_code < 500:
                    logger.info("%s is up (HTTP %d)", name, resp.status_code)
                    return True
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
                pass
            time.sleep(2)

        logger.warning("%s did not become healthy within %ds", name, DOCKER_HEALTH_TIMEOUT_SEC)
        return False


# ── ATHENA API Client ─────────────────────────────────────────────


class AthenaClient:
    """Async HTTP client for ATHENA dashboard API."""

    def __init__(self, base_url: str = DEFAULT_ATHENA_URL) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=30)

    async def close(self) -> None:
        await self._client.aclose()

    async def health_check(self) -> bool:
        """Verify ATHENA dashboard is running."""
        try:
            resp = await self._client.get("/api/status")
            return resp.status_code == 200
        except Exception:
            return False

    async def create_engagement(self, eid: str, name: str, target: str) -> dict:
        """Create a CTF engagement."""
        resp = await self._client.post("/api/engagements", json={
            "id": eid,
            "name": name,
            "target": target,
            "type": "web_app",
            "status": "active",
        })
        resp.raise_for_status()
        return resp.json()

    async def load_benchmark(self, file_path: str, engagement_id: str) -> dict:
        """Load benchmark challenges into ATHENA."""
        resp = await self._client.post(
            "/api/ctf/benchmark/load",
            params={"file_path": file_path, "engagement_id": engagement_id},
        )
        resp.raise_for_status()
        return resp.json()

    async def start_ctf_engagement(self, eid: str, target: str) -> dict:
        """Start the AI-powered CTF engagement."""
        resp = await self._client.post(
            f"/api/engagements/{eid}/ai-engage",
            params={"mode": "ctf", "target": target},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_scoreboard(self) -> dict:
        """Get current CTF scoreboard."""
        resp = await self._client.get("/api/ctf/scoreboard")
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json()

    async def get_challenges(self) -> list[dict]:
        """Get all challenges in the active CTF session."""
        resp = await self._client.get("/api/ctf/challenges")
        data = resp.json()
        return data.get("challenges", [])

    async def stop_ctf(self) -> dict:
        """Stop the CTF session and get final results."""
        resp = await self._client.post("/api/ctf/stop")
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json()

    async def stop_engagement(self, eid: str) -> dict:
        """Stop the AI engagement."""
        resp = await self._client.post(f"/api/engagements/{eid}/stop")
        return resp.json()


# ── Benchmark Runner ──────────────────────────────────────────────


class BenchmarkRunner:
    """Orchestrates a full benchmark run against ATHENA."""

    def __init__(
        self,
        bench_dir: Path,
        athena_url: str = DEFAULT_ATHENA_URL,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        engagement_id: str = DEFAULT_ENGAGEMENT_ID,
        challenges_filter: list[str] | None = None,
        difficulty_filter: int | None = None,
        resume_file: Path | None = None,
        dry_run: bool = False,
        sequential: bool = False,
    ) -> None:
        self.bench_dir = bench_dir
        self.timeout_sec = timeout_sec
        self.engagement_id = engagement_id
        self.dry_run = dry_run
        self.sequential = sequential

        self.client = AthenaClient(athena_url)
        self.docker = DockerManager()

        # Load and filter challenges
        all_challenges = load_benchmark(bench_dir)
        self.challenges = self._filter_challenges(
            all_challenges, challenges_filter, difficulty_filter
        )

        # Load resume state
        self.solved_names: set[str] = set()
        if resume_file and resume_file.exists():
            prev = json.loads(resume_file.read_text())
            self.solved_names = {
                r["name"] for r in prev.get("results", []) if r.get("solved")
            }
            logger.info("Resuming: %d challenges already solved", len(self.solved_names))

        # Results tracking
        self.results: list[dict[str, Any]] = []
        self.start_time = 0.0
        self._shutdown = False

    def _filter_challenges(
        self,
        challenges: list[dict],
        names: list[str] | None,
        difficulty: int | None,
    ) -> list[dict]:
        """Filter challenges by name or difficulty."""
        filtered = challenges
        if names:
            name_set = {n.lower() for n in names}
            filtered = [c for c in filtered if c["name"].lower() in name_set]
        if difficulty is not None:
            filtered = [c for c in filtered if c["difficulty"] == difficulty]
        return filtered

    async def run(self) -> dict[str, Any]:
        """Execute the full benchmark run. Returns results dict."""
        self.start_time = time.time()

        # Register signal handler for graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._signal_handler)

        try:
            return await self._run_benchmark()
        finally:
            self.docker.stop_all()
            await self.client.close()

    def _signal_handler(self) -> None:
        """Handle Ctrl+C gracefully."""
        logger.info("\nShutdown requested — stopping after current challenge...")
        self._shutdown = True

    async def _run_benchmark(self) -> dict[str, Any]:
        """Core benchmark execution logic."""
        total = len(self.challenges)
        skipped = [c for c in self.challenges if c["name"] in self.solved_names]
        pending = [c for c in self.challenges if c["name"] not in self.solved_names]

        logger.info(
            "═══════════════════════════════════════════════════════════════"
        )
        logger.info("ATHENA Benchmark Runner")
        logger.info(
            "═══════════════════════════════════════════════════════════════"
        )
        logger.info("Benchmark: %s", self.bench_dir.name)
        logger.info("Challenges: %d total, %d pending, %d previously solved",
                     total, len(pending), len(skipped))
        logger.info("Timeout: %ds per challenge", self.timeout_sec)
        logger.info("Mode: %s", "sequential" if self.sequential else "parallel (batched)")
        logger.info(
            "═══════════════════════════════════════════════════════════════\n"
        )

        if self.dry_run:
            return self._generate_dry_run_report(pending)

        # Verify ATHENA is running
        if not await self.client.health_check():
            logger.error(
                "ATHENA dashboard not reachable at %s. "
                "Start it with: cd tools/athena-dashboard && ./start.sh",
                self.client.base_url,
            )
            sys.exit(1)

        # Create engagement
        target = pending[0]["url"] if pending else "http://localhost:8080"
        try:
            await self.client.create_engagement(
                eid=self.engagement_id,
                name=f"Benchmark: {self.bench_dir.name}",
                target=target,
            )
        except httpx.HTTPStatusError:
            logger.info("Engagement %s may already exist — continuing", self.engagement_id)

        # Write benchmark.json for ATHENA to load
        bench_file = self.bench_dir / "benchmark.json"
        await self.client.load_benchmark(str(bench_file), self.engagement_id)
        logger.info("Loaded %d challenges into ATHENA CTF mode\n", len(pending))

        if self.sequential:
            await self._run_sequential(pending)
        else:
            await self._run_batched(pending)

        # Stop engagement and collect final results
        final_scoreboard = await self.client.get_scoreboard()
        await self.client.stop_ctf()
        try:
            await self.client.stop_engagement(self.engagement_id)
        except Exception:
            pass

        return self._generate_report(final_scoreboard, skipped)

    async def _run_sequential(self, challenges: list[dict]) -> None:
        """Run challenges one at a time with per-challenge Docker lifecycle."""
        # Start AI engagement once
        target = challenges[0]["url"]
        await self.client.start_ctf_engagement(self.engagement_id, target)

        for i, ch in enumerate(challenges):
            if self._shutdown:
                break

            logger.info(
                "──── Challenge %d/%d: %s (difficulty %d, %d pts) ────",
                i + 1, len(challenges), ch["name"], ch["difficulty"], ch["points"],
            )

            # Start Docker container
            started = self.docker.start_challenge(
                ch["name"], Path(ch["compose_dir"]) if ch["compose_dir"] else None, ch["port"]
            )
            if not started:
                self.results.append({
                    "name": ch["name"],
                    "difficulty": ch["difficulty"],
                    "solved": False,
                    "reason": "docker_failed",
                    "time_sec": 0,
                    "cost_usd": 0,
                })
                continue

            # Monitor until solved or timeout
            result = await self._monitor_challenge(ch)
            self.results.append(result)

            # Stop Docker container
            self.docker.stop_challenge(ch["name"])

            # Log progress
            solved_count = sum(1 for r in self.results if r.get("solved"))
            logger.info(
                "Progress: %d/%d solved (%.1f%%)\n",
                solved_count, i + 1, solved_count / (i + 1) * 100,
            )

    async def _run_batched(self, challenges: list[dict]) -> None:
        """Run challenges in parallel batches with Docker lifecycle."""
        # Sort by difficulty (easy first for quick points)
        sorted_challenges = sorted(challenges, key=lambda c: c["difficulty"])

        # Start all Docker containers first
        logger.info("Starting Docker containers for all challenges...")
        for ch in sorted_challenges:
            if self._shutdown:
                break
            self.docker.start_challenge(
                ch["name"], Path(ch["compose_dir"]) if ch["compose_dir"] else None, ch["port"]
            )

        # Start AI engagement — it processes all challenges through CTF mode
        target = sorted_challenges[0]["url"]
        await self.client.start_ctf_engagement(self.engagement_id, target)

        # Monitor overall progress with global timeout
        global_timeout = self.timeout_sec * len(sorted_challenges)
        # Cap at 4 hours for large benchmarks
        global_timeout = min(global_timeout, 4 * 3600)

        logger.info(
            "AI engagement started. Monitoring for up to %d minutes...",
            global_timeout // 60,
        )

        deadline = time.time() + global_timeout
        last_solved = 0

        while time.time() < deadline and not self._shutdown:
            await asyncio.sleep(POLL_INTERVAL_SEC)

            scoreboard = await self.client.get_scoreboard()
            if not scoreboard:
                continue

            solved = scoreboard.get("challenges_solved", 0)
            total = scoreboard.get("challenges_total", 0)
            points = scoreboard.get("captured_points", 0)
            total_pts = scoreboard.get("total_points", 0)
            elapsed = scoreboard.get("elapsed_minutes", 0)
            cost = scoreboard.get("total_cost_usd", 0)

            if solved != last_solved:
                last_solved = solved
                rate = solved / total * 100 if total > 0 else 0
                logger.info(
                    "[%5.1fm] Solved: %d/%d (%.1f%%) | Points: %d/%d | Cost: $%.2f",
                    elapsed, solved, total, rate, points, total_pts, cost,
                )

            # All solved — done
            if solved >= total:
                logger.info("All challenges solved!")
                break

            # Stall detection: if no progress for 10 minutes, log warning
            # (ATHENA's own budget enforcement will handle actual stopping)

        # Collect per-challenge results from ATHENA
        all_challenges = await self.client.get_challenges()
        for ch_data in all_challenges:
            self.results.append({
                "name": ch_data.get("name", "unknown"),
                "difficulty": ch_data.get("difficulty", 1),
                "solved": ch_data.get("status") == "solved",
                "solved_by": ch_data.get("solved_by", ""),
                "flag": ch_data.get("flag", ""),
                "time_sec": ch_data.get("time_spent_sec", 0),
                "cost_usd": ch_data.get("cost_usd", 0),
                "tool_calls": ch_data.get("tool_calls", 0),
            })

    async def _monitor_challenge(self, ch: dict) -> dict:
        """Monitor a single challenge until solved or timeout."""
        start = time.time()
        deadline = start + self.timeout_sec

        while time.time() < deadline and not self._shutdown:
            await asyncio.sleep(POLL_INTERVAL_SEC)

            challenges = await self.client.get_challenges()
            for c in challenges:
                if c.get("name") == ch["name"] and c.get("status") == "solved":
                    elapsed = time.time() - start
                    return {
                        "name": ch["name"],
                        "difficulty": ch["difficulty"],
                        "solved": True,
                        "solved_by": c.get("solved_by", ""),
                        "flag": c.get("flag", ""),
                        "time_sec": round(elapsed, 1),
                        "cost_usd": c.get("cost_usd", 0),
                        "tool_calls": c.get("tool_calls", 0),
                    }

        elapsed = time.time() - start
        return {
            "name": ch["name"],
            "difficulty": ch["difficulty"],
            "solved": False,
            "reason": "timeout" if not self._shutdown else "shutdown",
            "time_sec": round(elapsed, 1),
            "cost_usd": 0,
        }

    def _generate_report(
        self,
        scoreboard: dict,
        skipped: list[dict],
    ) -> dict[str, Any]:
        """Generate the final benchmark report."""
        elapsed = time.time() - self.start_time

        # Include previously solved challenges in totals
        total_challenges = len(self.challenges)
        solved_new = sum(1 for r in self.results if r.get("solved"))
        solved_prev = len(skipped)
        solved_total = solved_new + solved_prev
        solve_rate = solved_total / total_challenges * 100 if total_challenges > 0 else 0
        total_cost = sum(r.get("cost_usd", 0) for r in self.results)

        # Per-difficulty breakdown
        by_diff: dict[int, dict] = {}
        for r in self.results:
            d = r.get("difficulty", 1)
            if d not in by_diff:
                by_diff[d] = {"total": 0, "solved": 0}
            by_diff[d]["total"] += 1
            if r.get("solved"):
                by_diff[d]["solved"] += 1
        for ch in skipped:
            d = ch.get("difficulty", 1)
            if d not in by_diff:
                by_diff[d] = {"total": 0, "solved": 0}
            by_diff[d]["total"] += 1
            by_diff[d]["solved"] += 1

        report = {
            "benchmark": self.bench_dir.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_minutes": round(elapsed / 60, 1),
            "challenges_total": total_challenges,
            "challenges_solved": solved_total,
            "solve_rate_pct": round(solve_rate, 1),
            "total_cost_usd": round(total_cost, 4),
            "cost_per_challenge_usd": round(total_cost / max(solved_new, 1), 4),
            "by_difficulty": by_diff,
            "results": self.results,
            "leaderboard_comparison": {
                name: {
                    "score": score,
                    "delta": round(solve_rate - score, 1),
                    "status": "AHEAD" if solve_rate > score else "BEHIND" if solve_rate < score else "TIED",
                }
                for name, score in LEADERBOARD.items()
            },
        }

        # Print summary
        self._print_report(report)

        return report

    def _generate_dry_run_report(self, pending: list[dict]) -> dict:
        """Print challenge list without running anything."""
        logger.info("DRY RUN — Challenges that would be executed:\n")
        for i, ch in enumerate(pending):
            docker_status = "Docker" if ch["compose_dir"] else "No Docker"
            logger.info(
                "  %3d. [D%d] %-30s %s  port=%d  tags=%s",
                i + 1,
                ch["difficulty"],
                ch["name"],
                docker_status,
                ch["port"],
                ",".join(ch["tags"]) or "none",
            )

        logger.info("\nTotal: %d challenges", len(pending))
        by_diff = {}
        for ch in pending:
            d = ch["difficulty"]
            by_diff[d] = by_diff.get(d, 0) + 1
        for d in sorted(by_diff):
            logger.info("  Difficulty %d: %d challenges", d, by_diff[d])

        return {"dry_run": True, "challenges": pending}

    @staticmethod
    def _print_report(report: dict) -> None:
        """Print a formatted summary to stdout."""
        print("\n" + "═" * 65)
        print("  ATHENA BENCHMARK RESULTS")
        print("═" * 65)
        print(f"  Benchmark:  {report['benchmark']}")
        print(f"  Duration:   {report['duration_minutes']} minutes")
        print(f"  Solved:     {report['challenges_solved']}/{report['challenges_total']}")
        print(f"  Solve Rate: {report['solve_rate_pct']}%")
        print(f"  Total Cost: ${report['total_cost_usd']:.2f}")
        print(f"  Cost/Solve: ${report['cost_per_challenge_usd']:.2f}")

        print("\n  Per-Difficulty Breakdown:")
        for d in sorted(report["by_difficulty"]):
            info = report["by_difficulty"][d]
            rate = info["solved"] / info["total"] * 100 if info["total"] > 0 else 0
            print(f"    D{d}: {info['solved']}/{info['total']} ({rate:.0f}%)")

        print("\n  Leaderboard Comparison:")
        for name, comp in report["leaderboard_comparison"].items():
            delta = comp["delta"]
            symbol = "+" if delta > 0 else ""
            status = comp["status"]
            print(f"    vs {name:20s}: {symbol}{delta:.1f}%  [{status}]")

        print("═" * 65)

        # Per-challenge results (sorted by difficulty)
        results = sorted(report["results"], key=lambda r: (r["difficulty"], r["name"]))
        print("\n  Challenge Results:")
        for r in results:
            status = "SOLVED" if r.get("solved") else "FAILED"
            icon = "+" if r.get("solved") else "-"
            agent = r.get("solved_by", "")
            cost = r.get("cost_usd", 0)
            secs = r.get("time_sec", 0)
            print(
                f"    {icon} [D{r['difficulty']}] {r['name']:30s}  "
                f"{status:6s}  {secs:6.0f}s  ${cost:.2f}  {agent}"
            )

        print()


# ── CLI Entry Point ───────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ATHENA Benchmark Runner — XBOW-compatible CTF benchmark orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/xbow-benchmarks                    # Run all challenges
  %(prog)s /path/to/benchmarks --difficulty 1           # Easy challenges only
  %(prog)s /path/to/benchmarks --challenges XBEN-001    # Specific challenge
  %(prog)s /path/to/benchmarks --dry-run                # List without running
  %(prog)s /path/to/benchmarks --sequential             # One at a time
  %(prog)s /path/to/benchmarks --resume results.json    # Skip already-solved

Leaderboard to beat: XBOW 85%% | Open-source 84.6%% | MAPTA 76.9%%
        """,
    )

    parser.add_argument(
        "benchmark_dir",
        type=Path,
        help="Path to benchmark directory containing benchmark.json",
    )
    parser.add_argument(
        "--athena-url",
        default=os.environ.get("ATHENA_URL", DEFAULT_ATHENA_URL),
        help=f"ATHENA dashboard URL (default: {DEFAULT_ATHENA_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("ATHENA_BENCH_TIMEOUT", DEFAULT_TIMEOUT_SEC)),
        help=f"Per-challenge timeout in seconds (default: {DEFAULT_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--engagement-id",
        default=DEFAULT_ENGAGEMENT_ID,
        help=f"Engagement ID to use (default: {DEFAULT_ENGAGEMENT_ID})",
    )
    parser.add_argument(
        "--challenges",
        nargs="+",
        help="Run only these challenges (by name)",
    )
    parser.add_argument(
        "--difficulty",
        type=int,
        choices=[1, 2, 3],
        help="Run only challenges of this difficulty (1=easy, 2=medium, 3=hard)",
    )
    parser.add_argument(
        "--resume",
        type=Path,
        help="Resume from a previous results JSON file (skip solved challenges)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for results JSON (default: results-<timestamp>.json)",
    )
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Run challenges one at a time with per-challenge Docker lifecycle",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List challenges without starting Docker or ATHENA",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Validate benchmark directory
    if not args.benchmark_dir.is_dir():
        logger.error("Benchmark directory not found: %s", args.benchmark_dir)
        sys.exit(1)

    # Run benchmark
    runner = BenchmarkRunner(
        bench_dir=args.benchmark_dir,
        athena_url=args.athena_url,
        timeout_sec=args.timeout,
        engagement_id=args.engagement_id,
        challenges_filter=args.challenges,
        difficulty_filter=args.difficulty,
        resume_file=args.resume,
        dry_run=args.dry_run,
        sequential=args.sequential,
    )

    report = asyncio.run(runner.run())

    # Save results
    if not args.dry_run:
        output_path = args.output or Path(
            f"results-{datetime.now().strftime('%Y-%m-%d-%H%M')}.json"
        )
        output_path.write_text(json.dumps(report, indent=2, default=str))
        logger.info("Results saved to %s", output_path)


if __name__ == "__main__":
    main()
