# ITHZ-MCP Local RAG

MCP31 adds an optional local RAG layer for ITHZ-MCP.

The default implementation is deliberately simple:

- no cloud service;
- no external embedding runtime;
- no vector database dependency;
- deterministic feature-hashing vectors over safe indexed units;
- hybrid packs that keep deterministic evidence and evidence gaps.

The source of truth remains project memory and source files. The RAG index is a derived cache.

## Simple Commands

For normal use:

```powershell
python -m ithz_mcp rag-context-pack --project . --query "gates risks next files" --out rag_pack.md
```

To prebuild or refresh the derived cache:

```powershell
python -m ithz_mcp rag-index-build --project .
python -m ithz_mcp rag-status --project .
```

To search directly:

```powershell
python -m ithz_mcp rag-search --project . --query "prompt memory secrets" --limit 10
```

For no-write use, for example in read-only smoke tests:

```powershell
python -m ithz_mcp rag-context-pack --project . --query "gates" --no-cache --read-only-index
```

`--read-only-index` requires an existing `.ithz_mcp/index/index.json` and refuses to build one.

## Storage

The derived cache is:

```text
.ithz_mcp/rag/rag_index.json
```

It can be rebuilt. It is not the long-term memory source.

## Pack Shape

RAG context packs contain:

- Hybrid RAG Evidence;
- Deterministic Backstop;
- Evidence Gaps.

This keeps the vector-like retrieval useful without hiding the fact that direct source inspection is still required before edits.

The built-in index records an explicit embedding identity (`local_feature_hashing_v1`, builtin revision, tokenizer, normalization and dimension). Cache hits require a matching dimension and source index hash; changing either rebuilds the index. Optional local multilingual providers are pluggable through the retrieval protocol and must provide the same identity fields. No multilingual uplift is claimed without an independently labelled offline measurement.

The bounded fixture runner is `experiments/mcp36_4_retrieval/run_benchmark.py`; its synthetic labels and transparent three-line corpus are not independent annotation or live-model evidence. The executed receipt is `experiments/mcp36_4_retrieval/mcp36_4_retrieval_receipt.json`. The test split has only one answerable query and one no-answer query. Answerable Recall@5/MRR are `1.0/1.0` for deterministic, lexical graph and hybrid retrieval, versus `0.0/0.0` for hashing RAG. No-answer accuracy is `0.0` for the three lexical modes and `1.0` for hashing RAG. Both failures are retained; this is not evidence of general or multilingual uplift. Metrics exclude no-answer queries from Recall/MRR and report them separately. No embedding model is enabled by default.

## Claims

Allowed:

- local RAG can improve candidate discovery on tested fixtures;
- local RAG can reduce blind broad reads when it points to useful evidence.

Not allowed:

- no general token-saving guarantee;
- no claim that vector databases are useless;
- no claim that feature-hashing vectors equal neural embeddings;
- no claim that ITHZ-MCP replaces Git or production databases.
