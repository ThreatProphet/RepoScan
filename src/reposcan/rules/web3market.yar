/*
  TP-2026-018: original-repository warning, before fetching any payload.

  This constrained signature recognizes the captured controller combination.
  It does not resolve the imported alias, prove source-to-sink flow, or prove
  startup activation. Ordinary whitespace and renamed call bindings are allowed;
  token-field renaming, alternate encodings, and omitted/false flags are outside
  this signature. Those variants must never be interpreted as safe.

  inline-array's true argument exposes Node globals. The API also evaluates
  source with a false or omitted flag; the flag does not enable evaluation.
*/
rule TP_DevelTask_Node_InlineArray_Remote_Execution
{
  meta:
    description = "Web3Market-style inline-array import, character-decoded fetch, JSON token extraction, and call context coexist"
    severity = "high"
    category = "report-pattern"
    confidence = "medium"
    reports = "TP-2026-018"
    reference = "https://threatprophet.com/posts/web3market-polygon-wallet-cache/"
  strings:
    $import = /require[ \t\r\n]{0,32}\([ \t\r\n]{0,32}["']inline-array["'][ \t\r\n]{0,32}\)/
    $decoded_fetch = /fetch[ \t\r\n]{0,32}\([ \t\r\n]{0,32}String[ \t\r\n]{0,32}\.[ \t\r\n]{0,32}fromCharCode[ \t\r\n]{0,32}\(/
    $json = /\.json[ \t\r\n]{0,32}\([ \t\r\n]{0,32}\)/
    $token_extract = /\{[ \t\r\n]{0,32}token[ \t\r\n]{0,32}\}[ \t\r\n]{0,32}=/
    $token_call = /\([ \t\r\n]{0,32}token[ \t\r\n]{0,32},[ \t\r\n]{0,32}true[ \t\r\n]{0,32}\)/
  condition:
    all of them
}
