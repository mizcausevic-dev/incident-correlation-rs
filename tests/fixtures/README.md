# Incident Card fixture provenance

`incident-card-prompt-injection.json` is the canonical
`examples/prompt-injection-support-agent.json` from the MIT-licensed
[AI Incident Card specification](https://github.com/mizcausevic-dev/ai-incident-card-spec)
at commit `a5a968266a0e132bd05f1561f7fcbde0b0f8ed9b`.

It tests only this crate's projection of `incident.id`,
`incident.severity`, top-level `summary`, and the
`affected.agent_card_uris` / `tool_card_uris` fields. Passing this test
does not mean the crate validates the upstream JSON Schema.
