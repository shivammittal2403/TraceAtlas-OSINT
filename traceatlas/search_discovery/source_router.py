"""Provider registry + source/engine routing (§5, §25).

Routing is objective-driven, never one hardcoded giant sequence: the router
picks providers whose capability matches the query's required source type and
operator needs, respecting health, quota and cost.
"""

from __future__ import annotations

import os

from traceatlas.search_discovery.providers.base import BaseSearchProvider
from traceatlas.search_discovery.query import QuerySpec


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, BaseSearchProvider] = {}

    def register(self, provider: BaseSearchProvider) -> None:
        self._providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> BaseSearchProvider | None:
        return self._providers.get(provider_id)

    def all(self) -> list[BaseSearchProvider]:
        return list(self._providers.values())

    def healthy(self) -> list[BaseSearchProvider]:
        return [p for p in self._providers.values() if p.health()]

    def capabilities_report(self) -> list[dict]:
        return [p.capabilities() for p in self._providers.values()]


def default_registry(*, allow_cloud: bool = True,
                     searxng_url: str | None = None,
                     github_token_env: str = "GITHUB_TOKEN") -> ProviderRegistry:
    """Instantiate real providers configured via environment (§14, §25).

    Cloud web engines require API keys (env vars); without keys they are NOT
    registered — we never pretend a provider works when it cannot be reached.
    Key-free lawful sources (DuckDuckGo lite endpoint, Wayback CDX, GitHub
    public search with optional token, SearXNG self-hosted) are available.
    """
    from traceatlas.search_discovery.providers.bing import BingProvider
    from traceatlas.search_discovery.providers.brave import BraveProvider
    from traceatlas.search_discovery.providers.duckduckgo import DuckDuckGoProvider
    from traceatlas.search_discovery.providers.github import GitHubSearchProvider
    from traceatlas.search_discovery.providers.google import GoogleProvider
    from traceatlas.search_discovery.providers.mojeek import MojeekProvider
    from traceatlas.search_discovery.providers.searxng import SearXNGProvider
    from traceatlas.search_discovery.providers.telegram_public import TelegramPublicProvider
    from traceatlas.search_discovery.providers.wayback import WaybackProvider
    from traceatlas.search_discovery.providers.yahoo import YahooProvider
    from traceatlas.search_discovery.providers.yandex import YandexProvider

    reg = ProviderRegistry()
    ddg = DuckDuckGoProvider()
    reg.register(ddg)                                   # key-free, tested endpoint
    reg.register(GitHubSearchProvider(token_env=github_token_env))
    reg.register(WaybackProvider())
    tg = TelegramPublicProvider()
    if tg.available():
        reg.register(tg)
    url = searxng_url or os.environ.get("SEARXNG_URL", "")
    if url:
        reg.register(SearXNGProvider(base_url=url))
    if allow_cloud:
        keyed = [
            GoogleProvider(), BingProvider(), BraveProvider(),
            MojeekProvider(), YahooProvider(), YandexProvider(),
        ]
        for prov in keyed:
            if not prov.capability.authentication_required or prov.token():
                reg.register(prov)
    return reg


_SOURCE_TYPE_PREFERENCE = {
    "code": ["github"],
    "archive": ["wayback"],
    "social": ["telegram_public"],
    "news": ["google", "bing", "brave", "duckduckgo"],
    "academic": ["google", "bing", "duckduckgo"],
    "web": ["google", "bing", "brave", "duckduckgo", "mojeek", "searxng",
            "yahoo", "yandex"],
}


class SourceRouter:
    """Choose which engines should run which query (§8, §25)."""

    def __init__(self, registry: ProviderRegistry, *, mode: str = "BALANCED"):
        self.registry = registry
        self.mode = mode

    def route(self, pq, spec: QuerySpec) -> list[tuple[BaseSearchProvider, str]]:
        """Return [(provider, reason)] for one planned query."""
        wanted = _SOURCE_TYPE_PREFERENCE.get(spec.required_source_type or "web",
                                             _SOURCE_TYPE_PREFERENCE["web"])
        out: list[tuple[BaseSearchProvider, str]] = []
        considered = 0
        for pid in wanted:
            prov = self.registry.get(pid)
            if prov is None or not prov.health():
                continue
            considered += 1
            compiled = prov.compile(spec)
            if not compiled.valid:
                continue
            # reject routes where essential ops were dropped (§5)
            essential_dropped = [d for d in compiled.dropped_ops
                                 if d.split(":")[0] in ("site", "filetype")
                                 and (spec.site or spec.filetypes)]
            if essential_dropped and spec.required_source_type != "web":
                continue
            if essential_dropped:
                # keep only if engine still adds coverage value
                if self.mode in ("FAST", "BALANCED"):
                    continue
            out.append((prov, f"capability match ({pid}); "
                              f"ops={'+'.join(compiled.supported_ops) or 'terms'}"))
        if spec.required_source_type in ("code", "archive", "social") or out:
            return out
        # web fallback: BALANCED caps at 3 engines/query to avoid redundancy (§8)
        cap = {"EXHAUSTIVE": 99, "BALANCED": 3, "FAST": 1,
               "VERIFICATION": 2}.get(self.mode, 3)
        return out[:cap]
