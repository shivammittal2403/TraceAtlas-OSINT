"""Source bias analysis (§10).

Bias analysis EXPLAINS incentives, position and limitations of a source.
It never automatically discards evidence: a biased source with strong primary
evidence keeps the fact, annotated with the bias.
"""

from traceatlas.trust.source_bias.model import BiasFlags, bias_for_source
from traceatlas.trust.source_bias.analyzer import SourceBiasAnalyzer
from traceatlas.trust.source_bias.scoring import risk_level_for
from traceatlas.trust.source_bias.explanation import explain_bias

__all__ = ["BiasFlags", "bias_for_source", "SourceBiasAnalyzer",
           "risk_level_for", "explain_bias"]
