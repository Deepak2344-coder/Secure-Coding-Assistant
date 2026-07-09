from dataclasses import dataclass

from retrieval_layer.embedder import query


@dataclass
class RetrievalResult:
    retrieved_text: str
    cwe_reference: str
    source_url: str


def retrieve(vuln_type: str, snippet: str) -> RetrievalResult | None:
    query_text = f"{vuln_type.replace('_', ' ')}: {snippet}"
    results = query(query_text, n_results=2)

    if not results:
        return None

    combined_text = "\n\n".join(r["document"] for r in results if r["document"])
    best = results[0]

    return RetrievalResult(
        retrieved_text=combined_text,
        cwe_reference=best["cwe_id"],
        source_url=best["source_url"],
    )
