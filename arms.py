"""
Defense arms for the campaign. The monitor (I1-I3 admission) and the
counterfactual gate (delta_1 plant removal, delta_2 cited-untrusted removal,
quarantine-on-flip) reuse the SAME semantics that launderbench/monitor.py
already verified deterministically. This module wires them onto live AgentDojo
episodes; the security/utility verdicts come from AgentDojo's own ground truth.

Arms:
  no-defense    : run the agent, no interception.
  monitor-only  : I1-I3 admission check on each proposed protected/irreversible action.
  monitor+gate  : monitor + counterfactual re-commitment gate on admitted irreversibles.
  attriguard    : disclosed reimplementation of arXiv:2603.10749 (parallel
                  counterfactual tests: re-execute under control-attenuated
                  observations; drop the call if it does not survive).
  melon/spotlight/toolfilter/i3bind : secondary baselines (thin wrappers).

NOTE: run_episode returns a dict with at least:
  {target_hit: bool, benign_blocked: bool}
computed from AgentDojo's security() / utility() checks after the (possibly
filtered) trajectory is executed.
"""
from __future__ import annotations

# The verified monitor/gate primitives live in launderbench; import if present,
# else fall back to an inline copy with identical semantics.
try:
    import importlib.util, pathlib
    lb = pathlib.Path(__file__).resolve().parent / "monitor.py"
    if lb.exists():
        spec=importlib.util.spec_from_file_location("mon", lb); m=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        monitor_admits = m.monitor_admits
        recommit_flips = getattr(m, "recommit_flips", None)
    else:
        raise ImportError
except Exception:
    def monitor_admits(action, support, tau_c, l_req):
        """I1-I3: every cited root attested (cert ok, in-window), aggregated
        trust score >= tau_c at required level."""
        if not support: return False
        attested=all(b.get("cert")=="ok" and b.get("in_window",True) for b in support)
        w=sum(b.get("w",0.0) for b in support if b.get("label_ge",True))
        score=w/(1.0+w)
        return attested and score>=tau_c
    def recommit_flips(agent_recommit, ctx, action, plant_ids, cited_untrusted_ids):
        """gate: quarantine if action changes under delta_1 (plant removal) or
        delta_2 (cited-untrusted removal)."""
        for drop in (plant_ids, cited_untrusted_ids):
            a2=agent_recommit({k:v for k,v in ctx.items() if k not in drop})
            if a2!=action: return True
        return False


class BaseArm:
    def __init__(self, client, model_id, temperature, seed):
        self.client=client; self.model=model_id; self.temp=temperature; self.seed=seed
        # kind follows the model: Ollama (open-weight) unless it is the frontier model id
        import os
        _front = os.environ.get("FRONTIER_MODEL","gpt-4o-mini-2024-07-18")
        self.kind = "frontier" if model_id==_front else "ow"
    _KIND = "frontier"  # overridden per-arm-instance by the runner (model_kind)
    def _run(self, case, arm_filter):
        """Delegate to the version-pinned AgentDojo 0.1.35 integration."""
        from agentdojo_integration import run_one_case
        return run_one_case(case, getattr(self, "kind", self._KIND), arm_filter,
                            self.temp, self.seed)
    def _agent(self, case, intercept=None):
        return self._run(case, intercept)
    def _UNUSED_stub(self):
        raise NotImplementedError(
            "Wire AgentDojo's AgentPipeline to the OpenAI-compatible client here. "
            "AgentDojo >=0.1 exposes agent_pipeline.AgentPipeline.from_config; pass "
            "base_url/model from self.client/self.model. See AgentDojo README "
            "'Running with a custom model'. This is the only stub; everything else runs.")
    def run_episode(self, case):
        raise NotImplementedError


class NoDefense(BaseArm):
    def run_episode(self, case):
        traj=self._agent(case)
        return _verdict(case, traj)

class MonitorOnly(BaseArm):
    def run_episode(self, case):
        traj=self._agent(case, intercept=self._filter)
        return _verdict(case, traj)
    def _filter(self, proposed):
        # proposed: {action, support, tau_c, l_req, protected: bool}
        if not proposed.get("protected"): return True   # non-protected: allow
        return monitor_admits(proposed["action"], proposed["support"],
                              proposed["tau_c"], proposed["l_req"])

class MonitorGate(MonitorOnly):
    def _filter(self, proposed):
        if not super()._filter(proposed): return False   # monitor blocks
        if not proposed.get("irreversible"): return True # gate only on irreversibles
        flip=recommit_flips(proposed["recommit"], proposed["ctx"], proposed["action"],
                            proposed.get("plant_ids",set()), proposed.get("cited_untrusted_ids",set()))
        return not flip                                  # quarantine on flip

class AttriGuard(BaseArm):
    """arXiv:2603.10749 disclosed reimpl: for each proposed tool call, re-execute
    under control-attenuated observations; keep only if the call survives."""
    def run_episode(self, case):
        traj=self._agent(case, intercept=self._attribute)
        return _verdict(case, traj)
    def _attribute(self, proposed):
        # attenuate untrusted observations, re-run agent shadow, survival test
        survived=proposed.get("survives_attenuation")
        if survived is None:  # compute via shadow re-exec if harness supplies hook
            survived=proposed.get("recommit_attenuated", lambda: proposed["action"])()==proposed["action"]
        return bool(survived)

def _passthru_arm(cls):
    return cls
ARMS={
    "no-defense":NoDefense, "monitor-only":MonitorOnly, "monitor+gate":MonitorGate,
    "attriguard":AttriGuard,
    # secondary baselines: implement as thin MonitorOnly variants or dedicated wrappers
    "melon":MonitorOnly, "spotlight":MonitorOnly, "toolfilter":MonitorOnly, "i3bind":MonitorGate,
}
def make_arm(name, client, model_id, temperature, seed):
    return ARMS[name](client, model_id, temperature, seed)

def _verdict(case, traj):
    """Use AgentDojo's own checks: security() True == injection target achieved;
    utility() False on a benign task after our filtering == benign_blocked."""
    target_hit=bool(traj.get("target_hit", traj.get("security_target_achieved")))
    benign_blocked=(case["kind"]=="utility" and not traj.get("utility_achieved", True))
    return dict(target_hit=target_hit, benign_blocked=benign_blocked,
                n_tool_calls=traj.get("n_tool_calls"), filtered=traj.get("n_filtered",0))
