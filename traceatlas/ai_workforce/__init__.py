"""TraceAtlas AI Workforce: hierarchical multi-agent intelligence employees.

The workforce is a REAL orchestration system — managers hold state, task queues,
permissions and budgets; employees execute declared skills through connectors;
nothing reaches canonical case truth without passing the Fact Gate in
``traceatlas.trust``. This is not a collection of persona prompts.
"""

__all__ = []  # Workforce is exported once traceatlas.ai_workforce.workforce exists


def __getattr__(name):  # lazy re-export to avoid import cycles during build-out
    if name == "Workforce":
        from traceatlas.ai_workforce.workforce import Workforce
        return Workforce
    raise AttributeError(name)
