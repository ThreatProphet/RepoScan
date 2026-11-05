# RepoScan repository review

**Result:** review-needed  
**Scan status:** complete  
**Target:** /tmp/reposcan-example-blfcdi61/web3market-entry  
**Tool:** RepoScan 0.3.1  
**Engine:** yara-python 4.5.4

This is a static review of supplied files. Findings identify material to inspect before trusting, installing, or running the project. No findings is not a guarantee of safety.

## Coverage

Scanned **2 of 2 selected files**. Completeness applies to the configured policy, not every byte in the repository.

| Policy skip | Count |
| --- | ---: |
| Ignored entries (directories may be pruned) | 0 |
| Oversized files | 0 |
| Symlinks | 0 |
| Special files | 0 |

## Findings

### 1. TP\_DevelTask\_Node\_InlineArray\_Remote\_Execution

**Priority:** high | **Confidence:** medium | **Category:** report-pattern  
**File:** controllers/users.js.fixture  
**Source:** yara-python

Web3Market-style inline-array import, character-decoded fetch, JSON token extraction, and call context coexist

| Evidence | Line | Byte offset | Length |
| --- | ---: | ---: | ---: |
| $import | 3 | 191 | 23 |
| $token\_extract | 7 | 300 | 11 |
| $decoded\_fetch | 7 | 325 | 26 |
| $json | 7 | 365 | 7 |
| $token\_call | 8 | 394 | 25 |

**Reports:** TP-2026-018

**References:** https://threatprophet.com/posts/web3market-polygon-wallet-cache/

**Scanned file SHA-256:** 3c518161baa8bec93a06b64f576f0d562956f970eef8bfe5bb1f0fbec0ad2838

### 2. REVIEW\_Encoded\_Character\_Array

**Priority:** medium | **Confidence:** high | **Category:** obfuscation  
**File:** models/User.js.fixture  
**Source:** static-review

A literal character-code array statically decodes to a URL; its use and destination require review.

| Evidence | Line | Byte offset | Length |
| --- | ---: | ---: | ---: |
| numeric-url-array | 3 | 166 | 119 |

**Reports:** TP-2026-018

**References:** https://threatprophet.com/posts/web3market-polygon-wallet-cache/

**Scanned file SHA-256:** fa1a6c1f0daf1adca89f98e8d63ec8145a3396db7133fb6397367b5ebde04570

### 3. REVIEW\_Character\_Code\_Decoder

**Priority:** low | **Confidence:** medium | **Category:** obfuscation  
**File:** controllers/users.js.fixture  
**Source:** static-review

Character-code construction can conceal strings or perform ordinary text handling.

| Evidence | Line | Byte offset | Length |
| --- | ---: | ---: | ---: |
| character-decoder | 7 | 331 | 20 |

**Scanned file SHA-256:** 3c518161baa8bec93a06b64f576f0d562956f970eef8bfe5bb1f0fbec0ad2838

## Reproducibility

**Schema:** 1.0  
**Rule-pack SHA-256:** fa6ddc2b9168bab96e39f5acfe2226cc1ffe8ad4215a2d64e0137ea604461f3e  
**Ignore policy SHA-256:** 9bc2647df302b1ff3741ee23a9e2117c7a75af2fc5e61a1b6cbc8f0774a58332

| Limit | Value |
| --- | ---: |
| max\_size | 2097152 |
| max\_files | 10000 |
| max\_total\_bytes | 268435456 |
| max\_entries | 100000 |
| timeout | 30 |
