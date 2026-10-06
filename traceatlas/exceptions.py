"""Exception hierarchy for TraceAtlas-Automator."""


class TraceAtlasError(Exception):
    """Base class for all TraceAtlas errors."""


class ConfigurationError(TraceAtlasError):
    """Invalid or missing configuration."""


class ValidationError(TraceAtlasError):
    """Domain object failed validation."""


class PolicyViolation(TraceAtlasError):
    """An action was refused by the policy engine."""


class SourceError(TraceAtlasError):
    """A source or connector failed."""


class EvidenceError(TraceAtlasError):
    """Evidence capture / integrity problem."""


class BudgetExceeded(TraceAtlasError):
    """Cost or quota budget exhausted."""


class KillSwitchActive(TraceAtlasError):
    """All autonomous activity is halted."""
