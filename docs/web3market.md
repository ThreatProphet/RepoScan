# Case study: adding the Web3Market entry pattern

Source investigation:
[TP-2026-018, Web3Market](https://threatprophet.com/posts/web3market-polygon-wallet-cache/).

## Developer decision

A developer receives a marketplace project and is asked to inspect or run it.
RepoScan should identify reasons to pause while the files are still being
reviewed as data. It should not need to start the application or retrieve the
next payload to issue a warning.

The investigation describes a startup path in which a controller reconstructs
an endpoint from character codes, fetches JSON, extracts a `token`, and supplies
it to the imported `inline-array` API. The endpoint data is supplied by a model
file, and the server invokes the controller after successfully listening.

The inspected `inline-array` 2.1.3 API evaluates source. Its boolean flag enables
Node globals; it does not switch evaluation on or off. A false or omitted flag
therefore does not make remotely supplied source safe. Package presence or use
with a fixed local literal is not, by itself, this malicious delivery pattern.
The project's version range and absence of a lockfile also prevent asserting
which exact version every installation resolved.

## Baseline and detection choice

Before this update, the original repository returned no findings under the
existing YARA and Lite rule packs. Web3Market had not yet been integrated; that
result establishes the starting point for the new report-derived detection.

The new canonical rule is
`TP_DevelTask_Node_InlineArray_Remote_Execution`. It recognizes the observed
same-file combination around the package import, character decoder, remote
JSON/token handling, and evaluation-call shape. It uses medium confidence and
describes a pattern that deserves review.

This is not a general JavaScript data-flow proof. The rule does not prove that
an arbitrary called identifier is bound to the imported API, trace every local
module, or establish successful execution. Its narrower syntax coverage is
intentional and tested. Alternate flag forms or transformations that it misses
remain limitations, not safe variants.

Common static-review checks provide independent warnings for supported
concealment and suspicious constructs. A complete startup chain is not required
before such observations can be shown.

## Reproduce the public example

The public fixture at `tests/fixtures/web3market-entry` contains reduced source
snippets in `.fixture` files. It uses a reserved `example.invalid` destination
and contains no installable target manifest or runnable entry point. Treat its
contents strictly as scanner input.

From a trusted RepoScan checkout with the canonical engine installed:

```bash
reposcan tests/fixtures/web3market-entry --engine yara-python --format text
reposcan tests/fixtures/web3market-entry --engine yara-python --format json
reposcan tests/fixtures/web3market-entry --engine yara-python --format markdown
```

A `review-needed` result with exit code `1` is expected from the canonical
engine. The fixture yields `TP_DevelTask_Node_InlineArray_Remote_Execution`,
`REVIEW_Character_Code_Decoder`, and `REVIEW_Encoded_Character_Array`. Review the
confidence, source locations, and report reference. The captured
[text](../examples/web3market.txt), [JSON](../examples/web3market.json), and
[Markdown](../examples/web3market.md) outputs are generated from this fixture;
they are not a transcript of malware execution.

## Tested expectations

The [detection-quality tests](../tests/test_detection_quality.py) and
[common-review tests](../tests/test_review.py) check exact rule identities and
the intended strength of a warning.

| Case | Required interpretation |
| --- | --- |
| Observed controller shape | Exactly `TP_DevelTask_Node_InlineArray_Remote_Execution` among canonical rules. |
| Supported quote/whitespace changes and renamed call binding | The same canonical ID remains present; this does not prove import binding. |
| Dependency declaration or fixed local evaluation alone | The Web3Market canonical ID is absent. Generic review warnings remain permissible. |
| Ordinary fetch alongside local evaluation | The tested close comparison does not match the Web3Market canonical ID. |
| Character-code array in the inert model | `REVIEW_Encoded_Character_Array`, without a claim of execution. |
| False or omitted evaluation flag | The narrow canonical signature misses; `REVIEW_Character_Code_Decoder` remains visible. This is a coverage boundary, not a safe variant. |

The preserved original repository and later stages can remain private
regression material. Public fixtures should keep the mechanism needed for the
test without carrying victim information or a working acquisition chain.

## Scope of the result

An entry-pattern finding helps the developer decide what to inspect before
startup. It does not establish that a remote stage was delivered, wallet data
was exposed, or an actor operated the repository. Later loader and wallet-cache
components are separate inputs and optional detection targets. Their absence
does not prevent a useful warning about the original project.
