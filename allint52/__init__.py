"""Standalone desktop intelligence panels; optional tools stay lazily loaded."""

PANELS = {
    'osint': ('osint', 'TraceAtlasOSINTPanel'),
    'socmint': ('socmint', 'TraceAtlasSOCMINTPanel'),
    'geoint': ('geomint', 'TraceAtlasGEOINTPanel'),
    'imint': ('imgmint', 'TraceAtlasIMINTPanel'),
    'audint': ('audint', 'TraceAtlasAUDINTPanel'),
    'vidint': ('vedmint', 'TraceAtlasVIDINTPanel'),
    'webint': ('webint', 'TraceAtlasWEBINTPanel'),
}
