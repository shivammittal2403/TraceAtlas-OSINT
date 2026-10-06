"""Canonical enumerations for the TraceAtlas domain model."""

from __future__ import annotations

from enum import Enum


class InvestigationStatus(str, Enum):
    DRAFT = "draft"
    PLANNED = "planned"
    RUNNING = "running"
    PAUSED = "paused"
    NEEDS_HUMAN = "needs_human"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ClaimStatus(str, Enum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNVERIFIABLE = "unverifiable"


class EvidenceTier(str, Enum):
    RAW = "raw"                # untouched captured bytes
    DERIVED = "derived"        # produced by a deterministic parser
    INTERPRETED = "interpreted"  # AI/human interpretation of raw material


class ConfidenceLevel(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class AuthorizationMode(str, Enum):
    PUBLIC_ONLY = "public_only"
    AUTHORIZED_PARTIAL = "authorized_partial"
    FULLY_AUTHORIZED = "fully_authorized"


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


class EntityType(str, Enum):
    PERSON = "person"
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    ASN = "asn"
    URL = "url"
    USERNAME = "username"
    SOCIAL_PROFILE = "social_profile"
    DOCUMENT = "document"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    EMAIL = "email"
    HASH = "hash"
    LOCATION = "location"
    EVENT = "event"
    CLAIM = "claim"
    UNKNOWN = "unknown"


class RelationshipType(str, Enum):
    MANAGES = "manages"
    OWNS = "owns"
    EMPLOYED_BY = "employed_by"
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    REGISTERED_BY = "registered_by"
    MENTIONS = "mentions"
    SAME_ENTITY_AS = "same_entity_as"
    AFFILIATED_WITH = "affiliated_with"
    LOCATED_AT = "located_at"
    RELATED_TO = "related_to"
    # infrastructure fabric (added with transform engine)
    DELEGATED_TO = "delegated_to"
    CERTIFICATE_FOR = "certificate_for"
    ISSUED_BY = "issued_by"
    IN_ASN = "in_asn"
    HOSTED_BY = "hosted_by"
    PUBLISHED = "published"
    LINKS_TO = "links_to"
    CONTAINS_OBSERVATION = "contains_observation"


class VerificationDecision(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    ESCALATED = "escalated"


class SourceQualification(str, Enum):
    DOCUMENTED = "documented"
    INTEGRATION_TESTED = "integration_tested"
    LIVE_VERIFIED = "live_verified"
    PRODUCTION_QUALIFIED = "production_qualified"
