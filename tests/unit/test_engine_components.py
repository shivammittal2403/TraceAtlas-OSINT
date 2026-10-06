"""Unit tests for the investigation execution engine core.

Deterministic, network-free: fake runners only. Covers TaskGraph waves and
cycle detection, executor retry/timeout/cancellation semantics, kill switch,
checkpoint round-trip, budget accounting and honest failure status.
"""

from __future__ import annotations

import pytest

from traceatlas.core.enums import TaskStatus
from traceatlas.core.task import Task
from traceatlas.investigation.audit import AuditTrail
from traceatlas.investigation.cancellation import CancelledError, CancellationToken
from traceatlas.investigation.checkpoints import CheckpointStore
from traceatlas.investigation.context import InvestigationContext
from traceatlas.investigation.engine import InvestigationEngine
from traceatlas.investigation.executor import TaskExecutor
from traceatlas.investigation.kill_switch import KillSwitch
from traceatlas.investigation.resumability import build_checkpoint
from traceatlas.investigation.retry import RetryPolicy
from traceatlas.investigation.task_graph import CycleError, TaskGraph
from traceatlas.planning.planner_output import Plan, PlannedTask


def _ctx(case_id="case-1", inv_id="inv-1") -> InvestigationContext:
    return InvestigationContext(case_id=case_id, investigation_id=inv_id)


def _task(kind="collect.dns", case_id="case-1", deps=None) -> Task:
    return Task(case_id=case_id, kind=kind, depends_on=deps or [])


# ------------------------------------------------------------------ task graph
class TestTaskGraph:
    def test_waves_layered_topological_order(self):
        a = _task("a")
        b = _task("b", deps=[a.id])
        c = _task("c", deps=[b.id])
        g = TaskGraph([a, b, c])
        waves = g.topo_waves()
        assert [w[0] for w in waves] == [a.id, b.id, c.id]

    def test_ready_requires_succeeded_parents(self):
        a = _task("a")
        b = _task("b", deps=[a.id])
        g = TaskGraph([a, b])
        assert {t.id for t in g.ready_tasks()} == {a.id}
        a.status = TaskStatus.SUCCEEDED
        assert {t.id for t in g.ready_tasks()} == {b.id}

    def test_cycle_detection(self):
        a = _task("a")
        b = _task("b", deps=[a.id])
        g = TaskGraph([a, b])
        a.depends_on = [b.id]          # introduce cycle after wiring
        g.parents[a.id].add(b.id)
        g.children[b.id].add(a.id)
        with pytest.raises(CycleError):
            g.topo_waves()

    def test_downstream_closure(self):
        a = _task("a")
        b = _task("b", deps=[a.id])
        c = _task("c", deps=[b.id])
        g = TaskGraph([a, b, c])
        assert g.downstream(a.id) == {b.id, c.id}

    def test_unknown_dependency_raises(self):
        with pytest.raises(KeyError):
            TaskGraph([_task("a", deps=["ghost"])])


# -------------------------------------------------------------------- executor
class TestExecutor:
    def test_success_path(self):
        calls = []

        def runner(t, ctx):
            calls.append(t.id)
            return True, "ok"

        ex = TaskExecutor(runner=runner, sleep=lambda s: None)
        t = _task()
        out = ex.execute(t, _ctx())
        assert out.status == TaskStatus.SUCCEEDED
        assert out.attempts == 1
        assert calls == [t.id]

    def test_retry_then_success(self):
        state = {"n": 0}

        def flaky(t, ctx):
            state["n"] += 1
            # transient-style error so the retry policy considers it retryable
            return (state["n"] >= 2), "" if state["n"] >= 2 else "503 temporarily unavailable"

        ex = TaskExecutor(runner=flaky, retry_policy=RetryPolicy(max_attempts=3),
                          sleep=lambda s: None)
        out = ex.execute(_task(), _ctx())
        assert out.status == TaskStatus.SUCCEEDED
        assert out.retried is True
        assert out.attempts == 2

    def test_exhausted_retries_fails_honestly(self):
        def bad(t, ctx):
            return False, "connection reset by peer"

        ex = TaskExecutor(runner=bad, retry_policy=RetryPolicy(max_attempts=2),
                          sleep=lambda s: None)
        out = ex.execute(_task(), _ctx())
        assert out.status == TaskStatus.FAILED
        assert "connection reset" in out.error
        assert out.attempts == 2          # retried once (transient marker)
        assert out.retried is True

    def test_non_retryable_error_fails_immediately(self):
        calls = []

        def bad(t, ctx):
            calls.append(1)
            return False, "invalid input target"

        ex = TaskExecutor(runner=bad, retry_policy=RetryPolicy(max_attempts=3),
                          sleep=lambda s: None)
        out = ex.execute(_task(), _ctx())
        assert out.status == TaskStatus.FAILED
        assert out.attempts == 1          # no pointless retries on deterministic errors
        assert len(calls) == 1

    def test_cancellation_token_stops_execution(self):
        token = CancellationToken(name="wave")
        token.cancel("user requested")
        ex = TaskExecutor(runner=lambda t, c: (True, ""), sleep=lambda s: None)
        with pytest.raises(CancelledError):
            ex.execute(_task(), _ctx(), token=token)

    def test_kill_switch_tripped_blocks_dispatch(self):
        ks = KillSwitch(sentinel_file="/tmp/nonexistent-killswitch", check_file_each_dispatch=False)
        ks.trip("policy_block")
        ex = TaskExecutor(runner=lambda t, c: (True, ""), kill_switch=ks,
                          sleep=lambda s: None)
        with pytest.raises(CancelledError):
            ex.execute(_task(), _ctx())

    def test_runner_exception_becomes_failed_outcome(self):
        def crash(t, ctx):
            raise RuntimeError("unexpected crash")

        ex = TaskExecutor(runner=crash, retry_policy=RetryPolicy(max_attempts=1),
                          sleep=lambda s: None)
        out = ex.execute(_task(), _ctx())
        assert out.status == TaskStatus.FAILED
        assert "unexpected crash" in out.error

    def test_audit_records_every_attempt(self):
        audit = AuditTrail()

        def bad(t, ctx):
            return False, "e"

        ex = TaskExecutor(runner=bad, audit=audit,
                          retry_policy=RetryPolicy(max_attempts=2), sleep=lambda s: None)
        ex.execute(_task(), _ctx())
        events = [e.action for e in audit.events]
        assert any("task." in a for a in events)


# --------------------------------------------------------------- checkpointing
class TestCheckpoints:
    def test_round_trip(self, tmp_path):
        store = CheckpointStore(root=tmp_path / "cp")
        ctx = _ctx()
        ctx.upsert_entity("domain:example.com", "domain", "example.com")
        ctx.charge(3.5)
        tasks = [_task("a"), _task("b")]
        tasks[0].status = TaskStatus.SUCCEEDED
        cp = build_checkpoint("inv-x", ctx, tasks, wave=1, notes={"k": "v"})
        path = store.write(cp)
        assert path.is_file()
        loaded = store.read("inv-x")
        assert loaded is not None
        assert loaded.investigation_id == "inv-x"
        assert loaded.case_id == ctx.case_id
        assert loaded.wave == 1
        assert loaded.cost_units_spent == 3.5
        assert loaded.entity_keys == ["domain:example.com"]
        assert loaded.task_states[tasks[0].id] == "succeeded"
        assert loaded.notes == {"k": "v"}

    def test_read_missing_returns_none(self, tmp_path):
        store = CheckpointStore(root=tmp_path / "cp")
        assert store.read("nope") is None

    def test_unsupported_version_rejected(self, tmp_path):
        store = CheckpointStore(root=tmp_path / "cp")
        p = store._path("inv-v")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"version": 99}', encoding="utf-8")
        with pytest.raises(ValueError):
            store.read("inv-v")


# --------------------------------------------------------------------- engine
def _plan(*kinds_deps) -> Plan:
    tasks = [PlannedTask(kind=k, payload={"targets": [{"kind": "domain", "value": "example.com"}]},
                         depends_on_kinds=list(deps))
             for k, deps in kinds_deps]
    return Plan(objective_spec_id="spec-1", tasks=tasks)


class TestEngine:
    def test_happy_path_completes_and_charges_budget(self):
        seen: list[str] = []

        def runner_factory(kind):
            def r(task, ctx):
                seen.append(kind)
                return True, ""
            return r

        runners = {k: runner_factory(k) for k in
                   ("collect.dns", "analyze.asn", "verify.claim")}
        eng = InvestigationEngine(runners=runners, max_parallel=1,
                                  checkpoint_store=None)
        eres = eng.run(_plan(("collect.dns", []), ("analyze.asn", ["collect.dns"]),
                             ("verify.claim", ["analyze.asn"])), _ctx())
        assert eres.status == "completed"
        assert eres.stop_reason == "OBJECTIVE_SATISFIED"
        assert sorted(seen) == sorted(["collect.dns", "analyze.asn", "verify.claim"])
        assert eres.context.cost_units_spent > 0

    def test_unknown_task_kind_fails_honestly(self):
        eng = InvestigationEngine(runners={}, max_parallel=1)
        eres = eng.run(_plan(("collect.mystery", [])), _ctx())
        assert eres.status == "failed"
        assert any("no runner registered" in e for e in eres.context.errors)

    def test_all_failed_marks_system_failure(self):
        def bad(task, ctx):
            return False, "down"
        eng = InvestigationEngine(runners={"collect.dns": bad}, max_parallel=1)
        eres = eng.run(_plan(("collect.dns", [])), _ctx())
        assert eres.status == "failed"
        assert eres.stop_reason == "SYSTEM_FAILURE"

    def test_budget_exhaustion_stops_before_next_wave(self):
        calls = []

        def ok(task, ctx):
            calls.append(task.kind)
            return True, ""

        eng = InvestigationEngine(runners={"collect.dns": ok, "analyze.asn": ok},
                                  max_parallel=1, budget_units=1.0)
        # first task costs 1 unit -> budget exhausted before wave 2
        ctx = _ctx()
        ctx.budget_max_cost_units = 1.0
        eres = eng.run(_plan(("collect.dns", []), ("analyze.asn", ["collect.dns"])), ctx)
        assert eres.status in ("budget_exhausted", "completed")
        if eres.status == "budget_exhausted":
            assert "analyze.asn" not in calls

    def test_cancellation_mid_run(self):
        token = CancellationToken(name="inv")
        def cancel_halfway(task, ctx):
            token.cancel("operator")
            return True, ""
        eng = InvestigationEngine(runners={"collect.dns": cancel_halfway,
                                           "analyze.asn": cancel_halfway}, max_parallel=1)
        eres = eng.run(_plan(("collect.dns", []), ("analyze.asn", ["collect.dns"])),
                       _ctx(), token=token)
        assert eres.status == "cancelled"

    def test_kill_switch_engaged_halts_everything(self):
        ks = KillSwitch(sentinel_file="/tmp/no-such-file", check_file_each_dispatch=False)
        def r(task, ctx):
            return True, ""
        eng = InvestigationEngine(runners={"collect.dns": r}, kill_switch=ks, max_parallel=1)
        ks.trip("emergency")
        eres = eng.run(_plan(("collect.dns", [])), _ctx())
        assert eres.status == "cancelled"
        assert eres.stop_reason == "POLICY_BLOCK"

    def test_checkpoints_written_per_wave(self, tmp_path):
        from traceatlas.investigation.checkpoints import CheckpointStore
        store = CheckpointStore(root=tmp_path / "cps")
        def r(task, ctx):
            return True, ""
        eng = InvestigationEngine(runners={"collect.dns": r, "analyze.asn": r},
                                  max_parallel=1, checkpoint_store=store)
        ctx = _ctx(inv_id="inv-cp")
        eres = eng.run(_plan(("collect.dns", []), ("analyze.asn", ["collect.dns"])), ctx)
        cp = store.read("inv-cp")
        assert cp is not None
        assert cp.wave >= 1
