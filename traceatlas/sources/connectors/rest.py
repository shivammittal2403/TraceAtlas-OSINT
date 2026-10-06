"""REST JSON connector: configurable API endpoint returning JSON records.

Used by many catalog sources (same shape, different base_url/headers). Supports
simple key-based pagination and jq-lite dotted extraction of record lists.
"""

from __future__ import annotations

import json

from traceatlas.core.validation import is_http_url
from traceatlas.sources.connectors.base import (
    BaseConnector, ConnectorManifest, ConnectorRequest, ConnectorResponse,
)
from traceatlas.sources.connectors.http_client import HttpFetcher


def dig(obj: object, path: str) -> list | None:
    """Follow a dotted path like 'data.results' into nested dicts; return list or None."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur if isinstance(cur, list) else None


class RestConnector(BaseConnector):
    name = "rest"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.base_url = str(self.config.get("base_url", ""))
        self.headers = dict(self.config.get("headers", {}))
        self.records_path = str(self.config.get("records_path", ""))
        self.page_param = str(self.config.get("page_param", ""))
        self.max_pages = int(self.config.get("max_pages", 3))
        self._http = HttpFetcher()

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            id=str(self.config.get("manifest_id", "connector.rest")),
            name=str(self.config.get("manifest_name", "REST JSON API")),
            source_id=str(self.config.get("source_id", "source.rest")),
            capabilities=["rest.json"],
            input_types=["query", "domain", "ip", "url"],
            output_types=["record.json"],
            rate_limit_rps=float(self.config.get("rate_limit_rps", 1.0)),
            cost_per_query_usd=float(self.config.get("cost_per_query_usd", 0.0)),
            requires_credentials=bool(self.config.get("requires_credentials", False)),
        )

    def validate_config(self) -> list[str]:
        problems = []
        if not is_http_url(self.base_url):
            problems.append("base_url must be a valid http(s) URL")
        return problems

    def _build_params(self, request: ConnectorRequest) -> dict:
        params = dict(request.params)
        qkey = str(self.config.get("query_param", "q"))
        if request.query:
            params[qkey] = request.query
        if request.target:
            tkey = str(self.config.get("target_param", ""))
            if tkey:
                params[tkey] = request.target
        return params

    def fetch(self, request: ConnectorRequest) -> ConnectorResponse:
        problems = self.validate_config() + self.validate_input(request)
        if problems:
            return ConnectorResponse(ok=False, error="; ".join(problems))
        self._throttle()
        try:
            resp = self._http.get(self.base_url, headers=self.headers or None,
                                  params=self._build_params(request))
            ok = resp.status_code == 200
            return ConnectorResponse(ok=ok, status_code=resp.status_code, body=resp.content,
                                     headers=dict(resp.headers), elapsed_ms=resp.elapsed_ms,
                                     redirect_chain=resp.redirect_chain,
                                     error="" if ok else f"http {resp.status_code}")
        except Exception as e:
            return ConnectorResponse(ok=False, error=f"rest call failed: {e}")

    def search(self, request: ConnectorRequest) -> list[ConnectorResponse]:
        """Paginated search when page_param configured; stops on empty page/error."""
        if not self.page_param:
            return [self.fetch(request)]
        responses: list[ConnectorResponse] = []
        for page in range(1, self.max_pages + 1):
            req = ConnectorRequest(url=request.url, query=request.query, target=request.target,
                                   params={**request.params, self.page_param: page})
            r = self.fetch(req)
            responses.append(r)
            if not r.ok:
                break
            recs = self.normalize(r)
            if not recs:
                break
        return responses

    def normalize(self, response: ConnectorResponse) -> list[dict]:
        if not response.ok:
            return []
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            if self.records_path:
                found = dig(data, self.records_path)
                if found is not None:
                    return [d for d in found if isinstance(d, dict)]
            return [data]
        return []

    def extract_observations(self, response: ConnectorResponse) -> list[dict]:
        obs: list[dict] = []
        for i, rec in enumerate(self.normalize(response)):
            obs.append({"predicate": "record.json", "subject": self.manifest().id,
                        "obj": json.dumps(rec, sort_keys=True)[:4000],
                        "attributes": {"index": i}})
        return obs
