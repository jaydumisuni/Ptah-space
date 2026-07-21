# OpenAI ChatGPT Projects and Work behavioural donor

Status: accepted for architecture study only — no source-code reuse and no proprietary implementation claim

Observed: 2026-07-21

## Donor identity

- Product family: OpenAI ChatGPT
- Behavioural surfaces: Projects, project memory, project instructions, files and Library, ChatGPT Work, Canvas and Scheduled Tasks
- Owner: OpenAI
- Source availability: proprietary product; public documentation and direct product behaviour only
- Ptah classification: Tier D product-behaviour and documentation donor
- Ptah subsystem: Workspace composition, context compilation, Artifact reuse, long-running agent work and human approval
- Integration decision: Study only
- Code reuse: none
- Licence decision: no OpenAI source code, internal prompts, hidden policies, schemas or proprietary implementation may be copied or inferred

## Official public sources

The candidate is grounded only in the following public sources:

1. Projects in ChatGPT  
   https://help.openai.com/en/articles/10169521-projects-in-chatgpt
2. File storage and Library in ChatGPT  
   https://help.openai.com/en/articles/20001052/library-for-chatgpt
3. ChatGPT Work and Codex  
   https://help.openai.com/en/articles/20001275/chatgpt-work-and-codex
4. What is the canvas feature in ChatGPT and how do I use it?  
   https://help.openai.com/en/articles/9930697/what-is-the-canvas-feature-in-chatgpt-and-how-do-i-use-it
5. Scheduled Tasks in ChatGPT  
   https://help.openai.com/en/articles/10291617/tasks-in-chatgpt

These URLs are evidence of documented product behaviour, not a licence to reproduce OpenAI software.

## Verified behavioural capabilities

Public documentation describes a project-scoped work surface that can:

- group related chats, reference files and project instructions;
- apply project instructions inside the project;
- use project memory and prioritize project chats and files;
- support project-only memory boundaries;
- allow eligible project sharing and shared project context;
- preserve uploaded and generated files in a reusable Library;
- carry project context into long-running Work sessions;
- expose progress, steering and approval points during longer work;
- provide editable revisioned writing/code surfaces through Canvas;
- schedule one-off, recurring or change-triggered work;
- keep scheduled work separate from project files when that product limitation applies.

## Architecture patterns to borrow

Ptah may borrow the following product-level patterns:

1. **Project envelope** — one durable scope for purpose, instructions, files, chats, tools and memory.
2. **Project-scoped inheritance** — new Sessions inherit accepted Workspace policy and authoritative context.
3. **Context prioritization** — relevant project records are preferred over unrelated history.
4. **Memory isolation** — project-only scope prevents cross-Workspace context leakage.
5. **Reusable Artifact Library** — uploaded and generated files remain discoverable beyond one Session.
6. **Parallel Sessions** — separate work threads share one Workspace without collapsing into one transcript.
7. **Long-running Work** — a multi-step agent can expose progress, request input and produce finished Artifacts.
8. **Editable Views** — users can directly revise an Artifact while an agent works against the same revision history.
9. **Scheduled continuation** — durable work may resume on a timer or condition.
10. **Human steering and approval** — important actions remain interruptible and reviewable.

## Patterns Ptah must improve

Ptah should not reproduce hidden or provider-bound memory. It should improve the pattern through:

- explicit source authority and provenance;
- inspectable context packets;
- model-independent Workspace state;
- local-first storage and execution;
- exported handoff checkpoints;
- per-Workspace Facility Grants;
- deterministic privacy and audience boundaries;
- exact Activity, Receipt and Artifact evidence;
- scheduled Activities that receive only explicitly granted Workspace Artifacts;
- fail-closed separation between generated candidates and accepted truth.

## Mapping to existing Ptah primitives

The donor does not justify a new `ChatGPTProject` core entity.

| Donor behaviour | Existing Ptah composition |
|---|---|
| Project | Workspace |
| Chat or work thread | Session plus Activity/Event history |
| Uploaded or generated file | Object, Revision and Artifact |
| Project instruction | Policy/configuration Artifact |
| Project memory | Workspace-scoped Knowledge View |
| Tool or app | Facility or Provider |
| Connected account | Provider identity plus Grant |
| Canvas | editable View over revisioned Objects |
| Scheduled task | timer/condition-triggered durable Activity |
| Shared project | Workspace membership, roles and Grants |
| Long-running Work | durable Recipe/Activity graph |
| Finished deliverable | Artifact plus provenance and Receipt |

## Boundaries

This donor record:

- does not change any frozen WP01–WP14 contract;
- does not claim OpenAI internal architecture;
- does not copy source, prompts, schemas or product assets;
- does not make OpenAI a Ptah runtime dependency;
- does not make Hunter dependent on ChatGPT;
- does not authorize any runtime implementation;
- does not weaken the current physical-host, closure-review or ADR-0033 gates.

## Conclusion

ChatGPT Projects and Work are accepted as a behavioural donor for the composition layer that lets humans and agents remain inside one long-running project. Ptah must implement the capability using Ptah-owned, inspectable and provider-independent primitives.
