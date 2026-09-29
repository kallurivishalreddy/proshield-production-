"""ProShield V3 Phase 5.1 — Capability Registry package."""
from .errors import (
    CapabilityAlreadyExistsError,
    CapabilityAuthorizationError,
    CapabilityConfigurationError,
    CapabilityNotFoundError,
    CapabilityPersistenceError,
    CapabilityStateError,
    CapabilityManagementError,
)
from .models import (
    CAPABILITIES_COLLECTION,
    Capability,
    CapabilityId,
    CapabilityStatus,
    CapabilityView,
    ImplementationRef,
    MappingProfile,
)
from .registry import CapabilityRegistry, can_transition
from .repository import (
    CAPABILITY_INDEX_SPECS,
    CAPABILITIES_VALIDATOR,
    CapabilityRepository,
    capability_collection_name,
)
from .seeds import BUILTIN_CAPABILITIES, build_builtin_capabilities
from .service import CapabilityService

__all__ = [
    "BUILTIN_CAPABILITIES",
    "CAPABILITIES_COLLECTION",
    "CAPABILITIES_VALIDATOR",
    "CAPABILITY_INDEX_SPECS",
    "Capability",
    "CapabilityAlreadyExistsError",
    "CapabilityAuthorizationError",
    "CapabilityConfigurationError",
    "CapabilityId",
    "CapabilityManagementError",
    "CapabilityNotFoundError",
    "CapabilityPersistenceError",
    "CapabilityRegistry",
    "CapabilityRepository",
    "CapabilityService",
    "CapabilityStatus",
    "CapabilityView",
    "ImplementationRef",
    "MappingProfile",
    "build_builtin_capabilities",
    "can_transition",
    "capability_collection_name",
]
