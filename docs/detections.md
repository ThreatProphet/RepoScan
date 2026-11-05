# Detection guide

RepoScan combines patterns derived from investigations with broader review
warnings. A developer does not need a confirmed malware-family match to have a
reason to inspect a repository before proceeding.

## Three identifiable sources

| ID prefix | Source | Interpretation |
| --- | --- | --- |
| `TP_DevelTask_*` | Canonical YARA rule | A matched rule from the selected pack; inspect its evidence and confidence. |
| `HEUR_*` | Explicit Lite matcher | An approximate heuristic, not a canonical YARA result. |
| `REVIEW_*` | Common static review | A supported configuration or source pattern worth reviewing; available with every engine. |

The authoritative canonical predicates and metadata are in
[`src/reposcan/rules/`](../src/reposcan/rules/), including the new
[`web3market.yar`](../src/reposcan/rules/web3market.yar). Common checks and their
`REVIEW_RULES` catalog are in [`review.py`](../src/reposcan/review.py). Lite
predicates are maintained separately in the scanner. Similar names do not
promise identical coverage.

## Mechanism coverage

| Family | Relevant input | What a warning means |
| --- | --- | --- |
| Git triggers | Supplied hook files, selected command-bearing configuration, includes, and metadata pointers | Review the hook event, configured path or command, and activation prerequisites. References are reported without following them. |
| VS Code tasks | `.vscode` and `.code-workspace` task/settings/debug declarations | Review automatic activation, commands, and referenced tasks before enabling the workspace or debugger. |
| Package commands | Lifecycle and project script declarations | Review unexpected interpreters, downloads, or script targets before invoking the associated command. |
| Concealed code | Character arrays, decoder tables, encoded commands, long whitespace gaps | Inspect content that is difficult to review directly; behavior may remain unresolved. |
| Remote execution patterns | Network input combined with dynamic evaluation or an interpreter | A risky combination is present; the detector may establish co-occurrence rather than binding or reachability. |
| Collection patterns | Environment, browser, wallet, clipboard, and sensitive-file operations | The source contains collection-related primitives; a match does not establish successful collection. |
| Web3Market entry | The observed `inline-array`, character decoder, fetch/JSON and token-call combination | A same-file pattern from report TP-2026-018 is present. |

Existing canonical rules retain their prior report IDs. Those IDs refer to the
source investigations in the [ThreatProphet archive](https://threatprophet.com/).
The Web3Market update adds a new report to that coverage; its earlier baseline
miss was not a regression of a previously integrated report.

## Warning strength

Severity indicates potential impact or urgency. Confidence indicates the
specificity of the evidence. A broad warning remains useful when the purpose of
the code is unknown.

Examples of appropriate interpretations:

- A dynamic evaluation construct can be a review warning without proof that
  its input is remote.
- A concealed URL can warrant inspection without proving the endpoint is
  malicious.
- An ordinary minified bundle is not a strong malware finding merely because
  it has long lines or high entropy.
- A quoted example in documentation can remain visible as context without
  being described as executed source.
- A legitimate updater may share risky mechanisms with a loader. The finding
  should identify the mechanism and leave its intended use open to review.

Paths such as `docs`, `vendor`, and `dist` are not declarations of safety. The
configured scope may skip some of them, and that exclusion is reported. Within
the selected scope, context should affect interpretation rather than silently
erase a supported warning.

## Known limits

This version does not build a complete JavaScript call graph or establish
arbitrary data flow between files. Its narrow Web3Market rule does not resolve
every import alias, encoding, response-field name, or call form. Unsupported
forms are detection limits, not evidence that they are safe.

`REVIEW_Configuration_Unparsed` and `REVIEW_Analysis_Limit` expose supported
parser and work bounds. They can occur in an operationally complete scan;
`complete: true` does not remove the need to resolve those warnings. See the
[design note](design.md#coverage-and-completeness) for the concrete bounds.
Lexical matching may also find comments and strings, so a match alone does not
establish that the text is active code.

A repository scan sees only supplied bytes. It cannot identify an absent
downloaded payload, infer the contents of an unresolved dependency, or prove
that a browser accepted a later-stage modification. Decoded or reconstructed
representations must be identified separately from original response bytes.

Exact domains, hashes, blockchain identifiers, and wallet IDs can support
correlation, but ordinary infrastructure or a targeted wallet identifier is not
a standalone maliciousness verdict. A match also does not assign an actor or
establish a real identity.

## Extending coverage

Use the [contribution process](../CONTRIBUTING.md): state the observed behavior,
write a bounded predicate, retain exact expected IDs, challenge it with close
benign cases, and document what it cannot establish. Tests should distinguish a
correct review warning from an unsupported strong verdict.
