"""Falsification machinery (§19).

The FalsificationEmployee uses this to try to DISPROVE the leading hypothesis.
It must not treat a 'winning' hypothesis as something to defend: any approved
fact that contradicts the hypothesis statement weakens/falsifies it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import Hypothesis, HypothesisStatus

_FALSIFY_MARKERS = {
    "ownership": ["no ownership record", "different owner", "owner mismatch",
                  "unrelated registration"],
    "timeline": ["timeline conflict", "did not exist at the time", "after the event",
                 "impossible date"],
    "identity": ["identity mismatch", "different person", "not the same entity"],
    "infrastructure": ["cdn", "shared hosting", "proxy", "parked domain",
                       "common hosting provider"],
    "source_dependency": ["single upstream source", "all derived from", "syndicated"],
    "stale": ["historical association", "no longer", "expired", "former configuration"],
    "parsing_error": ["parse error", "malformed record", "scanner false positive"],
}

_NEG = re.compile(r"\b(does not|didn't|doesnt|is not|was not|never|no longer)\b")


@dataclass
class FalsificationReport:
    hypothesis_id: str
    attempted_tests: list[str] = field(default_factory=list)
    breaking_facts: list[str] = field(default_factory=list)
    alternative_explanations_found: list[str] = field(default_factory=list)
    outcome: HypothesisStatus = HypothesisStatus.INCONCLUSIVE
    explanation: str = ""

    def to_dict(self) -> dict:
        return {"hypothesis_id": self.hypothesis_id,
                "attempted_tests": list(self.attempted_tests),
                "breaking_facts": list(self.breaking_facts),
                "alternative_explanations_found": list(self.alternative_explanations_found),
                "outcome": self.outcome.value, "explanation": self.explanation}


def falsification_questions(hypothesis: Hypothesis) -> list[str]:
    """§19 standard question set the falsifier must ask."""
    return [
        "what fact would make this hypothesis false?",
        "what identity mismatch could break it?",
        "what timeline conflict could break it?",
        "what source dependency weakens it?",
        "what alternative explanation fits the same facts?",
        "what independent source can test it?",
    ]


class FalsificationEngine:
    def __init__(self, memory: CaseMemory) -> None:
        self.memory = memory

    def test(self, hypothesis: Hypothesis) -> FalsificationReport:
        report = FalsificationReport(hypothesis_id=hypothesis.id)
        report.attempted_tests = falsification_questions(hypothesis)

        # 1) explicitly declared falsification conditions matched by approved facts
        approved = self.memory.approved_facts
        for cond in hypothesis.falsification_conditions:
            low = cond.lower()
            for fact in approved:
                stmt = fact.statement.lower()
                markers = next((ms for k, ms in _FALSIFY_MARKERS.items() if k in low), [])
                hit = any(m in stmt for m in markers) or _topic_overlap(cond, fact.statement)
                if hit and fact.id not in hypothesis.supporting_facts:
                    report.breaking_facts.append(fact.id)

        # 2) opposing facts already recorded against the hypothesis
        for fid in hypothesis.opposing_facts:
            if fid in {f.id for f in approved} and fid not in report.breaking_facts:
                report.breaking_facts.append(fid)

        # 3) alternatives that fit the same evidence better. A competing
        #    hypothesis counts as an alternative explanation once it is offered
        #    for the same question — even when only one side has been granted
        #    supporting facts so far (the falsifier's job is to test the leading
        #    story against its rival, §17).
        seen_alternatives: set[str] = set()
        for other in self.memory.hypotheses.values():
            if other.id == hypothesis.id:
                continue
            fits_same_facts = set(other.supporting_facts) >= set(hypothesis.supporting_facts)
            shares_question = bool(other.question) and other.question == hypothesis.question
            if not (fits_same_facts or shares_question):
                continue
            label = getattr(other, "statement", None) or str(other)
            if label not in seen_alternatives:
                seen_alternatives.add(label)
                report.alternative_explanations_found.append(label)

        # 4) competing-hypothesis falsification (§17/§19). A declared
        #    falsification condition is only meaningful if some approved fact
        #    actually engages it. Deterministic ways to engage one:
        #      (a) a fact carrying a known falsifying marker for that condition's
        #          topic family ("different owner", "cdn/shared hosting", …);
        #      (b) a fact sharing substantive content terms with the condition;
        #      (c) RIVAL-EXPLANATION TEST: the hypothesis claims a fact PROVES an
        #          inference ("X proves Y"). If an approved fact states that very
        #          observation is fully explained by something other than Y, then
        #          the proof claim fails and that fact breaks the hypothesis —
        #          even when the hypothesis cites that same fact as support.
        #          This is not circular: we are not doubting the observation, only
        #          the inference drawn from it.
        if not report.breaking_facts:
            cond_terms = _condition_terms(hypothesis.falsification_conditions)
            supported = set(hypothesis.supporting_facts)
            for fact in approved:
                engages = (_marker_hit(fact.statement, hypothesis.falsification_conditions)
                           or _matches_condition(fact.statement, cond_terms))
                if not engages and fact.id in supported:
                    continue   # supporting facts may not falsify via lexical overlap alone
                if not engages and _rival_explanation_breaks(hypothesis, fact,
                                                            self.memory.approved_facts):
                    engages = True
                if engages and fact.id not in report.breaking_facts:
                    report.breaking_facts.append(fact.id)

        if report.breaking_facts:
            decisive = len(report.breaking_facts) >= max(1, len(approved) // 2)
            report.outcome = (HypothesisStatus.FALSIFIED if decisive
                              else HypothesisStatus.WEAKENED)
            report.explanation = (
                f"{len(report.breaking_facts)} approved fact(s) contradict the hypothesis; "
                f"outcome={report.outcome.value}. The falsifier defends evidence, not the story.")
        elif report.alternative_explanations_found:
            report.outcome = HypothesisStatus.INCONCLUSIVE
            report.explanation = ("no direct falsifier found, but an alternative explains the "
                                  "same supporting facts equally: ambiguity retained, confidence "
                                  "cannot rise above inconclusive (§17)")
        else:
            report.outcome = HypothesisStatus.TESTING
            report.explanation = "no falsifying evidence yet; required tests remain open"
        return report

    def apply(self, hypothesis: Hypothesis, report: FalsificationReport) -> Hypothesis:
        hypothesis.status = report.outcome
        hypothesis.contradictions.extend(report.breaking_facts)
        if report.outcome == HypothesisStatus.FALSIFIED:
            hypothesis.confidence = hypothesis.confidence.VERY_LOW \
                if hasattr(hypothesis.confidence, "VERY_LOW") else hypothesis.confidence
        return hypothesis


def _topic_overlap(a: str, b: str) -> bool:
    ta = {w for w in re.findall(r"[a-z0-9._-]{5,}", a.lower())}
    tb = {w for w in re.findall(r"[a-z0-9._-]{5,}", b.lower())}
    if not ta or not tb:
        return False
    overlap = len(ta & tb) / min(len(ta), len(tb))
    neg_a, neg_b = bool(_NEG.search(a)), bool(_NEG.search(b))
    return overlap >= 0.5 and neg_a != neg_b


# Generic connective/auxiliary words that carry no topic signal; used to keep
# falsification-condition matching from firing on boilerplate alone.
_STOPWORDS = frozenset("""
a an the and or but if then than that this these those of to in on at by with
from as is are was were be been being do does did doing have has had having
it its it's they them their there here which who whom whose what when where
how why all any both each few more most other some such no nor not only own
same so too very can will just should now also into about across between
per via using use used uses within without upon under over above below
""".split())

_MIN_TERM_LEN = 4

# Domain-neutral function words are not enough on their own: a fact must also
# share at least one substantive (non-stopword, >=6 chars) term with the
# declared condition before it can be treated as engaging that condition.
_SUBSTANTIVE_MIN_LEN = 6


def _condition_terms(conditions: list[str]) -> set[str]:
    """Content terms extracted from declared falsification conditions."""
    terms: set[str] = set()
    for cond in conditions or []:
        for word in re.findall(r"[a-z0-9][a-z0-9._-]*", (cond or "").lower()):
            if len(word) >= _MIN_TERM_LEN and word not in _STOPWORDS:
                terms.add(word)
    return terms


def _marker_hit(statement: str, conditions: list[str]) -> bool:
    """True when an approved fact's statement carries a known falsification
    marker for the topic family named by any declared condition (§19).

    Example: condition "same organization CONTROLS both domains" belongs to the
    ``ownership`` family, so an approved fact stating a different owner / no
    ownership record breaks it — even though its wording shares no tokens.
    """
    stmt = (statement or "").lower()
    for cond in conditions or []:
        markers = next((ms for k, ms in _FALSIFY_MARKERS.items() if k in cond.lower()), [])
        if any(m in stmt for m in markers):
            return True
    return False


def _matches_condition(statement: str, cond_terms: set[str]) -> bool:
    """True when an approved fact's statement shares enough content terms with a
    declared falsification condition to count as engaging that condition (§19).

    Deterministic lexical test — deliberately conservative: it requires at least
    two shared content terms AND at least one shared substantive term, so
    incidental overlap of generic vocabulary ("domain", "date", "record") can
    never manufacture a falsifier.
    """
    if not cond_terms:
        return False
    stmt_terms = {w for w in re.findall(r"[a-z0-9][a-z0-9._-]*", statement.lower())
                  if len(w) >= _MIN_TERM_LEN and w not in _STOPWORDS}
    if not stmt_terms:
        return False
    shared = cond_terms & stmt_terms
    if len(shared) < 2:
        return False
    return any(len(w) >= _SUBSTANTIVE_MIN_LEN for w in shared)


# Inference verbs: a hypothesis of the shape "<observation> PROVES/MEANS/SHOWS
# <inference>" is an argument from evidence, not the evidence itself. A rival
# explanation of the same observation therefore attacks the inference (§19).
_INFERENCE_VERBS = ("proves", "means", "shows", "demonstrates", "indicates",
                    "confirms", "establishes")

# Verbs that assert a rival causal account. "explains" is included because an
# approved fact such as "CDN shared hosting explains identical IPs across
# unrelated tenants" states a general mechanism that accounts for the very
# observation a hypothesis treats as proof (§19).
_ALTERNATIVE_MARKERS = (
    "explained by", "is explained by", "fully explained by", "consistent with",
    "can be explained", "alternative explanation", "better explained",
    "attributable to", "due to", "caused by", "accounted for by",
    "explains",
)

# Words that name the subject/topic rather than carrying analytic content.
_GENERIC_TERMS = frozenset("""
fact facts record records data evidence observation statement claim value type
thing things something nothing everything result results case item items
example true false proof prove proves proven mean means meant show shows shown
indicate indicates confirmed confirms explain explains explained
""".split())


def _proof_claim(hypothesis: Hypothesis) -> tuple[str, str] | None:
    """Split "<subject> <inference verb> <claim>" into its two halves."""
    low = hypothesis.statement.lower()
    for verb in _INFERENCE_VERBS:
        parts = low.split(f" {verb} ", 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            return parts[0].strip(), parts[1].strip()
    return None


def _content_terms(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9._-]*", (text or "").lower())
            if len(w) >= _MIN_TERM_LEN and w not in _STOPWORDS and w not in _GENERIC_TERMS}


def _rival_explanation_breaks(hypothesis: Hypothesis, fact, approved_facts) -> bool:
    """§19/§17 rival-explanation test.

    Returns True when ``fact`` states that the very observation the hypothesis
    treats as proof is instead explained by something else — which defeats the
    inference while leaving the observation intact.
    """
    claim = _proof_claim(hypothesis)
    if claim is None:
        return False
    subject, inferred = claim
    stmt_low = (fact.statement or "").lower()
    if not any(m in stmt_low for m in _ALTERNATIVE_MARKERS):
        return False

    # The fact must be about the SAME observation the hypothesis leans on.
    subj_terms = _content_terms(subject)
    fact_terms = _content_terms(fact.statement)
    if not subj_terms or not (subj_terms & fact_terms):
        return False

    # ...and it must NOT already assert the hypothesis's own inference
    # ("the identical IP proves common control" would support, not break).
    if _content_terms(inferred) <= fact_terms:
        return False

    # Finally, the rival explanation must be one the analyst has actually put on
    # record — as an alternative explanation carried by this hypothesis (the
    # HypothesisEngine fills these from every competing statement offered for the
    # same question, §17). Unrelated explanatory facts cannot falsify by accident.
    for rival in (hypothesis.alternative_explanations or []):
        if not rival:
            continue
        r_terms = _content_terms(rival)
        if not r_terms:
            continue
        new_terms = r_terms - subj_terms
        if new_terms and (new_terms & fact_terms):
            return True
    return False


__all__ = ["FalsificationReport", "FalsificationEngine", "falsification_questions"]
