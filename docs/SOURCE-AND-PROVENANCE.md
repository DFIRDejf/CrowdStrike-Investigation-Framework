# Source Attribution and Provenance

## Sources

1. **Existing user-reported validated queries** — supplied in the prior query pack. Copies are sanitized.
2. **`CS Queries.one` (user-provided)** — readable text contains training notes on filter-first design, groupBy, joins, regex, case, time formatting, helper functions and a larger selection of ATT&CK-oriented hunt candidates. Some content is image-backed, repeated or partially garbled in extracted text. We did **not** claim to reproduce unreadable screenshots or all OneNote pages.
3. **Official CQL function reference:** https://library.humio.com/crowdstrike-query-language/cql.html and https://library.humio.com/crowdstrike-query-language/functions.html
4. **Cool Query Friday**, r/crowdstrike, selected posts:
   - Parameterized process/DNS hunting: https://www.reddit.com/r/crowdstrike/comments/16soii4/
   - PowerShell newly seen DNS: https://www.reddit.com/r/crowdstrike/comments/1fqokic/
   - Browser extensions: https://www.reddit.com/r/crowdstrike/comments/1dl3bo5/
   - correlate(): https://www.reddit.com/r/crowdstrike/comments/1rquf4q/
   - explain:asTable(): https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/
   - setTimeInterval(): https://www.reddit.com/r/crowdstrike/comments/1t0zcsz/
   - Regex primer: https://www.reddit.com/r/crowdstrike/comments/1g1hw21/

## Attribution

Community examples are rewritten/adapted for teaching and hunting and are **not** represented as word-for-word reproductions or validated production detections. Always follow original links for detailed explanations and author credit.

## Sanitization

- Original employee names, organizational domains, endpoint names and internal network ranges are **not** included in the new examples.
- Previously migrated source queries are preserved as their earlier sanitized variants; audit before publishing in a wider audience.
- No internal lookup paths, sensor CIDs, tokens or case IDs should be stored here.
- Public release requires approval for corporate references and trademarks.

## Known Limitations

- `ProcessRollup2` and `DnsRequest` join examples supplied historically can join on process ID without agent ID; revise after environment review.
- Historic `PeFileWritten` query references `Activity_duration` without defining it.
- CQL field availability and event names vary; validate `fieldset()` and your tenant's licenses.
- The version that was previously reported working may differ from the published sanitized copy.
