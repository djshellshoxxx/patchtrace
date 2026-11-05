# Workflow fragments

`openai-agents-step.yml` preserves the development-agent step from commit `5d504ff5` verbatim. It is a reference fragment for a job's `steps` list. GitHub discovers executable workflows under `.github/workflows`; a standalone step there lacks the required workflow name, event, jobs, permissions and timeout structure and breaks repository workflow validation.

Any future runnable agent workflow needs its own review of ownership, credentials, publication, concurrency and budget controls alongside the existing automation proposals (#167, #170, #171 and #186). Relocating this fragment requires no API request or additional automation configuration.
