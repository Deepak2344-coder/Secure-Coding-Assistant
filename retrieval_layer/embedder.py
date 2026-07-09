from __future__ import annotations

from sentence_transformers import SentenceTransformer
import chromadb
from chromadb import PersistentClient

from retrieval_layer.corpus import CORPUS


EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHROMA_PATH = "chroma_data"
COLLECTION_NAME = "cwe_corpus"

_model: SentenceTransformer | None = None
_client = None
_collection = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBEDDING_MODEL)
    return _model


def _get_collection() -> chromadb.Collection:
    global _client, _collection
    if _collection is None:
        _client = PersistentClient(path=CHROMA_PATH)
        try:
            _collection = _client.get_collection(COLLECTION_NAME)
        except (ValueError, chromadb.errors.NotFoundError):
            _collection = _client.create_collection(COLLECTION_NAME)
            _index_corpus(_collection)
    return _collection


def _index_corpus(collection: chromadb.Collection) -> None:
    model = _get_model()
    texts = [chunk.text for chunk in CORPUS]
    ids = [f"{chunk.vuln_type}_{i}" for i, chunk in enumerate(CORPUS)]
    metadatas = [
        {"vuln_type": chunk.vuln_type, "cwe_id": chunk.cwe_id, "source_url": chunk.source_url}
        for chunk in CORPUS
    ]
    embeddings = model.encode(texts, show_progress_bar=False).tolist()
    collection.add(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=texts)


def query(query_text: str, n_results: int = 2) -> list[dict]:
    collection = _get_collection()
    model = _get_model()
    query_embedding = model.encode([query_text], show_progress_bar=False).tolist()[0]
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
    )
    output = []
    if results["ids"]:
        for i in range(len(results["ids"][0])):
            output.append({
                "document": results["documents"][0][i],
                "cwe_id": results["metadatas"][0][i]["cwe_id"],
                "source_url": results["metadatas"][0][i]["source_url"],
                "vuln_type": results["metadatas"][0][i]["vuln_type"],
                "score": results["distances"][0][i] if results.get("distances") else None,
            })
    return output
