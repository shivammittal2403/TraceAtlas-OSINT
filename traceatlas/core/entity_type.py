"""Registry of entity-type metadata (display names, key attributes)."""

from __future__ import annotations

from dataclasses import dataclass

from traceatlas.core.enums import EntityType


@dataclass(frozen=True)
class EntityTypeInfo:
    entity_type: EntityType
    label: str
    primary_key_attribute: str
    normalizer: str  # name of normalization function in entities.normalization


ENTITY_TYPES: dict[EntityType, EntityTypeInfo] = {
    EntityType.DOMAIN: EntityTypeInfo(EntityType.DOMAIN, "Domain", "domain", "domain"),
    EntityType.IP_ADDRESS: EntityTypeInfo(EntityType.IP_ADDRESS, "IP Address", "ip", "ip"),
    EntityType.ASN: EntityTypeInfo(EntityType.ASN, "Autonomous System", "asn", "asn"),
    EntityType.EMAIL: EntityTypeInfo(EntityType.EMAIL, "Email", "email", "email"),
    EntityType.USERNAME: EntityTypeInfo(EntityType.USERNAME, "Username", "username", "username"),
    EntityType.URL: EntityTypeInfo(EntityType.URL, "URL", "url", "url"),
    EntityType.HASH: EntityTypeInfo(EntityType.HASH, "File Hash", "hash", "hash_lower"),
    EntityType.PERSON: EntityTypeInfo(EntityType.PERSON, "Person", "name", "person_name"),
    EntityType.ORGANIZATION: EntityTypeInfo(
        EntityType.ORGANIZATION, "Organization", "name", "org_name"
    ),
}
