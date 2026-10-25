"""Observed usage contract. Unknown provider usage/cost must remain None."""
from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class UsageRecord:
    run_id: str
    call_id: str
    provider: str
    model: str
    input_tokens: int | None
    output_tokens: int | None
    input_price_per_million: Decimal | None
    output_price_per_million: Decimal | None
    price_as_of: str | None
    cache_hit: bool


def summarize_usage(records: tuple[UsageRecord, ...], request_count: int) -> dict[str, object]:
    """Later aggregate observed usage and separately labeled price estimates."""
    raise NotImplementedError("Usage aggregation awaits real pipeline calls")
