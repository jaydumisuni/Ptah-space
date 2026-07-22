# OpenAI ChatGPT Projects and Work behavioural donor

Status: corrected and accepted for application-experience study only — no source-code reuse and no proprietary implementation claim

Observed: 2026-07-21

Corrected boundary: 2026-07-22

## Donor identity

- Product family: OpenAI ChatGPT
- Behavioural surfaces: Projects, project memory, project instructions, files and Library, ChatGPT Work, Canvas and Scheduled Tasks
- Owner: OpenAI
- Source availability: proprietary product; public documentation and direct product behaviour only
- Ptah classification: Tier D product-behaviour and documentation donor
- Relevant layer: applications and user experiences built on Ptah Workspace primitives
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

Public documentation describes a project-scoped application surface that can:

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

## Patterns applications may borrow

Hunter, Sergeant, a human-facing shell or another application running on Ptah may borrow:

1. **Project envelope experience** — one application scope for related files, Sessions, tools and caller-owned metadata.
2. **Application-scoped instructions** — the application chooses whether and how to apply stored instruction Artifacts.
3. **Application context selection** — the application chooses relevant records and constructs its own context packet.
4. **Mechanical isolation** — Ptah Grants and Workspace boundaries prevent unauthorized cross-Workspace retrieval.
5. **Reusable Artifact Library** — uploaded and generated files remain discoverable beyond one Session.
6. **Parallel Sessions** — separate work threads use one Workspace substrate without collapsing into one transcript.
7. **Long-running application work** — Hunter or another caller plans work while Ptah executes and retains caller-defined Activities.
8. **Editable Views** — users revise Objects and Artifacts through application interfaces backed by Ptah revisions.
9. **Scheduled dispatch** — callers submit exact tasks and schedules for Ptah to persist and dispatch.
10. **Human steering and approval applications** — humans or approval systems decide whether work proceeds.

## Ptah boundary

Ptah does not borrow or own:

- context prioritization;
- source-authority ranking;
- interpretation of project instructions;
- blocker or next-action selection;
- review verdicts;
- approval decisions;
- candidate promotion;
- agent coordination.

Ptah provides neutral storage, execution, isolation, access enforcement, events, Artifacts, checkpoints and recovery. Applications provide intelligence and judgment.

## Improvements over provider-bound application state

Applications built on Ptah may improve the user experience through:

- caller-owned, inspectable records;
- exact source and Artifact provenance;
- provider-independent Workspace state;
- local-first storage and execution;
- exported caller-produced handoff checkpoints;
- mechanically enforced per-Workspace Facility Grants;
- explicit privacy and audience configuration;
- exact Activity, Receipt and Artifact evidence;
- scheduled Activities with exact caller-specified inputs;
- independent Sergeant review stored separately from Hunter output.

These are application and platform-composition properties. They do not make Ptah a decision-maker.

## Mapping to existing Ptah primitives

The donor does not justify a new `ChatGPTProject` Core entity.

| Donor behaviour | Ptah substrate | Caller/application responsibility |
|---|---|---|
| Project | Workspace | define purpose and meaning |
| Chat or work thread | Session plus Activity/Event history | choose conversation context |
| Uploaded or generated file | Object, Revision and Artifact | judge usefulness and correctness |
| Project instruction | stored Artifact/metadata | interpret and apply instruction |
| Project memory | Knowledge/View storage and retrieval | select relevance and trust |
| Tool or app | Facility or Provider | choose tool and desired operation |
| Connected account | Provider identity plus Grant | configure access authority |
| Canvas | editable View over revisioned Objects | present and edit content |
| Scheduled task | timer/condition-triggered Activity | choose task, inputs and outcome |
| Shared project | Workspace membership and Grants | decide membership policy |
| Long-running Work | durable Activity/Attempt/Receipt | plan, coordinate and evaluate work |
| Finished deliverable | Artifact plus provenance and Receipt | accept, reject or review result |

## Boundaries

This donor record:

- does not change any frozen WP01–WP14 contract;
- does not claim OpenAI internal architecture;
- does not copy source, prompts, schemas or product assets;
- does not make OpenAI a Ptah runtime dependency;
- does not make Hunter dependent on ChatGPT;
- does not assign context, authority, review or approval decisions to Ptah;
- does not authorize any runtime implementation;
- does not weaken the current physical-host, closure-review or ADR-0033 gates.

## Conclusion

ChatGPT Projects and Work remain useful as a behavioural donor for **applications** that let humans and agents remain inside one long-running project. Ptah supplies the neutral, inspectable and provider-independent platform underneath those applications; it does not decide what the project means or whether any result is correct.
