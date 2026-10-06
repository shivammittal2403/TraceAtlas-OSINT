"""Search-discovery error taxonomy (§43).

Provider failures are recorded, never hidden; results are never fabricated.
"""


class SearchDiscoveryError(RuntimeError):
    """Base class for all search/discovery errors."""


class QueryValidationError(SearchDiscoveryError):
    """A query failed deterministic validation and must not execute (§27)."""


class PolicyBlockedError(SearchDiscoveryError):
    """Query/target blocked by authorized scope or safety policy (§45)."""


class ProviderError(SearchDiscoveryError):
    def __init__(self, provider_id: str, message: str):
        super().__init__(f"[{provider_id}] {message}")
        self.provider_id = provider_id


class ProviderUnavailableError(ProviderError):
    """Provider is down / health check failed — retry/fallback tier applies."""


class RateLimitedError(ProviderError):
    """Provider rate limit / quota boundary hit (§41, §43 RATE_LIMITED)."""

    def __init__(self, provider_id: str, message: str = "rate limited",
                 retry_after: float = 1.0):
        super().__init__(provider_id, message)
        self.retry_after = retry_after


class PaginationError(ProviderError):
    """Pagination state inconsistent (page beyond max, cursor expired)."""


class BudgetExhaustedError(SearchDiscoveryError):
    """Query budget / cost ceiling reached; planner must stop the wave (§8, §41)."""


class CheckpointError(SearchDiscoveryError):
    """Checkpoint could not be read/written atomically."""
