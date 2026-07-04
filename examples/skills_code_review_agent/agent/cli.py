# Tencent is pleased to support the open source community by making tRPC-Agent-Python available.
#
# Copyright (C) 2026 Tencent. All rights reserved.
#
# tRPC-Agent-Python is licensed under Apache-2.0.
"""CLI for the skills code review agent example."""

from __future__ import annotations

import argparse
import json

from .input_resolver import FIXTURE_ORDER
from .orchestrator import ReviewOrchestrator
from .storage import DEFAULT_DB_URL


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the deterministic skills code review agent example.")
    subparsers = parser.add_subparsers(dest="command")

    review = subparsers.add_parser("review", help="run a review")
    review.add_argument("--diff-file")
    review.add_argument("--repo-path")
    review.add_argument("--fixture", choices=[*FIXTURE_ORDER, "all"])
    review.add_argument("--file-list")
    review.add_argument("--dry-run", action="store_true")
    review.add_argument("--runtime", choices=["container", "local", "auto", "cube"], default="container")
    review.add_argument("--db-url", default=DEFAULT_DB_URL)
    review.add_argument("--output-dir", default=None)

    query = subparsers.add_parser("query", help="query persisted review records")
    query.add_argument("--task-id", required=True)
    query.add_argument("--db-url", default=DEFAULT_DB_URL)

    eval_cmd = subparsers.add_parser("eval-fixtures", help="run all fixtures and write eval_summary.json")
    eval_cmd.add_argument("--dry-run", action="store_true")
    eval_cmd.add_argument("--runtime", choices=["container", "local", "auto", "cube"], default="container")
    eval_cmd.add_argument("--db-url", default=DEFAULT_DB_URL)
    eval_cmd.add_argument("--output-dir", default=None)

    return parser


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        report = ReviewOrchestrator(db_url=DEFAULT_DB_URL).review(fixture="all", dry_run=True, runtime="local")
        _print_json(
            {
                "task_id": report.task_id,
                "conclusion": report.conclusion,
                "report_paths": report.report_paths,
                "database_query": report.database_query,
            }
        )
        return 0
    if args.command == "review":
        report = ReviewOrchestrator(db_url=args.db_url, output_dir=args.output_dir).review(
            diff_file=args.diff_file,
            repo_path=args.repo_path,
            fixture=args.fixture,
            file_list=args.file_list,
            dry_run=args.dry_run,
            runtime=args.runtime,
        )
        _print_json(
            {
                "task_id": report.task_id,
                "conclusion": report.conclusion,
                "findings": len(report.findings),
                "warnings": len(report.warnings),
                "needs_human_review": len(report.needs_human_review),
                "report_paths": report.report_paths,
                "database_query": report.database_query,
            }
        )
        return 0
    if args.command == "query":
        _print_json(ReviewOrchestrator(db_url=args.db_url).query(task_id=args.task_id))
        return 0
    if args.command == "eval-fixtures":
        summary = ReviewOrchestrator(db_url=args.db_url, output_dir=args.output_dir).eval_fixtures(
            dry_run=args.dry_run,
            runtime=args.runtime,
        )
        _print_json(summary)
        return 0
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

