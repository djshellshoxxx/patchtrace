Preview interpretation context
Interpretation is optional. Select one or more function matches, wait for the current worker to finish, then choose Interpret selection or press Ctrl+I.
Read all three preview sections:
Section	What to inspect
Exact context	The selected evidence and code supplied to the model
Exact system prompt	Instructions accompanying that context
Omitted / unavailable	Material excluded by budget or availability


Check the match count, context digest, and approximate token estimate. The estimate does not guarantee that the request fits a particular model’s context window.
Choose the provider kind, endpoint, and exact model name. The documented transports support loopback Ollama and HTTPS OpenAI-compatible Chat Completions. The openai label identifies the protocol; it does not establish compatibility with every service.
Remote Ollama hosts, remote HTTP endpoints, endpoint redirects, environment-proxy forwarding, and native Anthropic Messages API are documented as unsupported.
Enter the request credential when required. It remains in memory for that request. Provider, endpoint, and model preferences can be remembered, so inspect them each time.
Select Send context only after reviewing the payload and destination. To change the character budget, edit Setup and reopen the preview to regenerate the context.
Malformed responses or invalid citations produce a failed attempt rather than accepted findings.
UNVERIFIED: live provider compatibility is an open acceptance item in the reviewed README. Mocked transport tests do not resolve it.
Sources: README.md, “Optional AI interpretation”; docs/specs/ui.md; src/patchtrace/tooltips.py.
