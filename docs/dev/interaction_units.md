Interaction-Unit (IU) Model
===========================

Purpose
• Provide a stable vocabulary for talking about *shapes* of patch hunks.
• Drive deterministic, LLM-free unit tests.
• Clarify contracts between the pure-algorithm part of Mephala and the
  LLM-assisted orchestration layer.

Base IU types
-------------
IU-1  INSERTION              (I)
IU-2  DELETION               (D)
IU-3  REPLACEMENT            (D followed by I)
IU-4  OVERLAP-INSERT         (I anchor originally inside a D range;
                              anchor fixed by Backporter._normalize_threads)

Orthogonal flags
----------------
W   whitespace-only payload
V   near-duplicate / variable rename
R   filename/path rename

Lifecycle
---------
Upstream diff ──► generate_actions()  ──► IU pattern emerges  
                 (iu.py helpers can classify)

IU-list ──► LLM alignment ──► threads  
threads  ──► _normalize_threads()     – resolves IU-4 anchor overlap  
threads  ──► weave()                  – materializes final Hunk

Tests
-----
tests/core/
    test_generate_actions.py   (IU-1…4 creation)
    test_normalize_threads.py  (anchor fixes)
    test_weave.py              (resulting DiffLine sequence)
    test_validators.py         (structural sanity)
    test_candidate_finder.py   (W/V influence on search)
    test_finalize_patch.py     (mixed IU consolidation)
