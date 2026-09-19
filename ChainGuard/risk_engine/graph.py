"""
Interaction Graph Generation

Builds a deterministic graph of the analyzed address's counterparties from
its transaction history: the central address, the wallets/contracts it
interacted with, and which of those are flagged in the threat-intel
dataset. This is generated directly from transaction data — never
fabricated, and never produced by an LLM.
"""

from typing import List, Dict, Any
from collections import defaultdict

from core.models import (
    AddressType,
    InteractionGraph,
    InteractionGraphNode,
    InteractionGraphEdge,
)

DEFAULT_MAX_COUNTERPARTY_NODES = 25


def build_interaction_graph(
    address: str,
    transactions: List[Any],
    is_contract: bool,
    flagged_addresses: List[str],
    contract_classification: Dict[str, bool] = None,
    max_counterparty_nodes: int = DEFAULT_MAX_COUNTERPARTY_NODES,
) -> InteractionGraph:
    """
    Build an InteractionGraph from a transaction list.

    Args:
        address: the analyzed (central) address
        transactions: normalized Transaction objects (blockchain.provider.Transaction)
        is_contract: whether the central address is itself a contract
        flagged_addresses: lowercase addresses present in the threat-intel dataset
        contract_classification: address(lowercase) -> is_contract, best-effort
        max_counterparty_nodes: cap on distinct counterparty nodes (excludes the central node)

    Returns:
        InteractionGraph with the central node, up to `max_counterparty_nodes`
        counterparties (ranked by interaction count), and one edge per
        counterparty aggregating all transactions with it.
    """
    address = address.lower()
    flagged_set = {a.lower() for a in flagged_addresses}
    contract_classification = contract_classification or {}

    interactions: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "value_sum": 0.0})

    for tx in transactions:
        counterparty = tx.to_address if tx.from_address.lower() == address else tx.from_address
        if not counterparty:
            continue
        counterparty = counterparty.lower()
        interactions[counterparty]["count"] += 1
        interactions[counterparty]["value_sum"] += tx.value or 0.0

    ranked = sorted(interactions.items(), key=lambda kv: kv[1]["count"], reverse=True)
    truncated = len(ranked) > max_counterparty_nodes
    top_counterparties = ranked[:max_counterparty_nodes]

    nodes: List[InteractionGraphNode] = [
        InteractionGraphNode(
            address=address,
            type=AddressType.CONTRACT if is_contract else AddressType.EOA,
            is_central=True,
            is_flagged=address in flagged_set,
            interaction_count=len(transactions),
        )
    ]

    edges: List[InteractionGraphEdge] = []

    for counterparty, stats in top_counterparties:
        node_type = AddressType.UNKNOWN
        if counterparty in contract_classification:
            node_type = AddressType.CONTRACT if contract_classification[counterparty] else AddressType.EOA

        nodes.append(
            InteractionGraphNode(
                address=counterparty,
                type=node_type,
                is_central=False,
                is_flagged=counterparty in flagged_set,
                interaction_count=stats["count"],
            )
        )
        edges.append(
            InteractionGraphEdge(
                from_address=address,
                to_address=counterparty,
                edge_type="contract_interaction" if node_type == AddressType.CONTRACT else "transaction",
                count=stats["count"],
                value_sum=round(stats["value_sum"], 6),
            )
        )

    return InteractionGraph(nodes=nodes, edges=edges, truncated=truncated)
