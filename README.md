# Mephala the Webspinner, the Patching Machine  
### End-to-end helper for back-porting upstream security patches to older distro releases

---

## What it does

Mephala automates the drudgery of turning *upstream* security patches into *down-stream* (e.g. Ubuntu LTS) back-ports.

High-level pipeline

1. Parse all `patches/*.patch` belonging to your package.  
2. Let you pick a target Ubuntu release.  
3. Run `quilt push` in *dry-run* mode and classify each hunk (clean, fuzz, fail).  
4. For fuzz/fail hunks, locate “candidate” regions in the target tree via a fuzzy search engine.  
5. Ask an LLM (OpenAI Chat Completions API) to draft, prune and align the back-port against that candidate.  
6. Produce a brand-new hunk, weave it into a stand-alone `.patch` file and test-apply it with quilt.

The result is a tree of artefacts under `.metadata/`:

```
.metadata/
└─ <patch-name>/
   └─ <release>/
      └─ <hunk-id>/
         ├─ auto.patch        # machine-generated hunk
         ├─ choices.txt       # full candidate dump for diagnostics
         └─ unresolved.txt    # reason if we gave up
```

---

## Features

• Interactive *wizard* mode and unattended *auto-wizard* mode  
• Singleton wrapper around the OpenAI API (respects global rate limits)  
• Strict YAML/JSON parsing of model replies – less hallucination pain  
• Pure-Python fuzzy scanner (replaceable) to find likely match regions  
• Works inside a local package checkout; no network access to code hosts required  
• Runs every quilt command inside an isolated workspace and rolls back on failure  

---

## Installation

```bash
git clone https://github.com/<you>/mephala.git
cd mephala
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Packages used:

* openai ≥ 1.14  
* rich, typer, questionary – CLI UX  
* rapidfuzz (or fuzzywuzzy) – similarity scoring  
* intervaltree – candidate consolidation  
* PyYAML, json  

---

## Configuration

### 1. OpenAI credentials

Mephala looks for a **.gpt-conf** JSON file *in the same directory as* `mephala/ai/agent.py`.

```jsonc
{
  "API_KEY": "sk-…",
  "MODEL":   "gpt-4o"
}
```

Resolution order:

1. Explicit kwargs when you instantiate `Agent(model=…, api_key=…)`  
2. Environment variables `OPENAI_MODEL`, `OPENAI_API_KEY`  
3. `.gpt-conf`

### 2. Runtime metadata

Most runtime state lives in `metadata.yaml` in your current working directory; you do **not** edit it by hand — Mephala fills values as it runs (package name, path links, CVE descriptions, …).

### 3. Static environment

`core/config/.env-conf` is a project-local JSON file that lists:

```json
{
  "release_list": ["focal", "jammy", "kinetic", "lunar"],
  "package_workspace": "/workspace/packages",
  "ubuntu-cve-tracker": "/workspace/ubuntu-cve-tracker"
}
```

---

## Quick start

```bash
# example session
cd <my-package-dir>          # must contain patches/*.patch
mephala wizard               # guided, one hunk at a time
#  …or…
mephala auto-wizard          # churn through every hunk automatically
```

When Mephala prompts you:

* pick the upstream patch file
* pick the Ubuntu release you want to back-port to
* inspect candidates / choose best match
* accept or reject the generated hunk

Accepted hunks are written to `.metadata/…/auto.patch` and can be
copied into a real quilt series.

---

## Directory layout (developer view)

```
mephala/
├─ ai/          # OpenAI agent + Backporter orchestration
├─ core/
│  ├─ diff/     # pure diff algorithms (Hunk, Patch, weaving)
│  ├─ models/   # value objects, enums
│  ├─ services/ # CandidateFinder, PatchManager, PackageManager
│  └─ config/   # ContextManager & env-conf
└─ cli/         # Typer entry points and helpers
```

---

## Logging

Activate basic logging:

```python
from mephala.core.utils.logging import configure
configure("DEBUG")
```

or use the env var:

```bash
export PYTHONLOGLEVEL=DEBUG
```

---

## Development & testing

1. Run unit tests

```bash
pytest
```

2. Style & static analysis

```bash
ruff check .
mypy
```

3. Regenerate requirements

```bash
pip-compile --extra dev -o requirements-dev.txt
```
