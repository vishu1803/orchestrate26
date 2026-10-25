"""Optional extraction-only model boundary. No provider/network calls in Phase 0."""
from typing import Protocol
from .models import Observation, SourceRef


class EvidenceExtractor(Protocol):
    """Implementations must validate schema, source IDs, spans and timestamps."""

    def extract(self, content: bytes, source: SourceRef) -> tuple[Observation, ...]:
        """Return grounded observations or an explicit extraction error."""
        ...
