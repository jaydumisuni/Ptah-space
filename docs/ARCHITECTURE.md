# Ptah Space Architecture

**Status:** Proposed canonical architecture for Phase 0B review  
**Implementation:** Not started

## 1. Definition

Ptah Space is an independent, open-source, online-first, concurrent digital world where humans and compatible software systems can upload, download, open, decompose, inspect, run, build, browse, transform, render, compare, store, resume, and recover files, repositories, applications, firmware, devices, environments, and artifacts.

Ptah supplies the physical digital world. The caller supplies intent, reasoning, instructions, priorities, permissions, restrictions, and acceptance criteria.

## 2. Architectural laws

1. Ptah is the world, not the thinker.
2. A workspace is persistent and is not the same thing as an activity.
3. One workspace may run many independent activities concurrently.
4. Files are registered objects, not opaque blobs.
5. Original objects remain preserved; changes create versions or derivatives unless replacement is explicit.
6. Live internet is a normal capability.
7. Active work runs on fast local or node-local storage.
8. Durable objects and artifacts may be synchronized to object storage.
9. Online and local Ptah use the same contracts.
10. Ptah is polyglot; Rust is the operational chassis, not a rule to rewrite mature tools.
11. Existing work is inspected before replacement.
12. External projects are adopted, wrapped, adapted, hosted, or studied only after evidence and licence review.
13. Technical isolation protects world integrity; it is not an autonomous policy judgement.
14. Important results must be traceable to inputs, activities, tools, environments, and evidence.

## 3. World model

```text
Clients
Web · Desktop · CLI · SDK · API · MCP · IDE
                         │
                         ▼
World Catalogue
Projects · Workspaces · Objects · Activities · Sessions
Nodes · Facilities · Artifacts · Storage Locations
                         │
                         ▼
Relay and Activity Plane
Live Events · Durable Workflows · Progress · Recovery
Cancellation · Dependency Graphs · Result Routing
             │                           │
             ▼                           ▼
Object and Decomposition Plane     Workspace Plane
Detection · Object Graphs          Providers · Filesystems
Derivatives · Provenance           Processes · Services
Domain Packs · Comparison          Concurrent Activities
             │                           │
             └─────────────┬─────────────┘
                           ▼
Facilities
Transfer · Git · Terminal · Build · Browser · Containers
Documents · Media · Firmware · Applications · Devices
Storage · Databases · Search · Rendering · Provenance
                           │
                           ▼
Nodes
Online Linux · Local Appliance · Windows · macOS · GPU
Android Devices · Emulators · Remote Machines
```

## 4. Canonical entities

### Object

Anything Ptah can store, inspect, transform, mount, compare, or execute.

Minimum identity:

```text
object_id
workspace_id
name
detected_type
declared_type
content_hash
size
source
parent_object_id
child_object_ids
storage_locations
metadata
available_views
available_operations
derivative_objects
producing_activity_id
schema_version
created_at
```

### Workspace

A persistent shared namespace containing files, objects, repositories, services, terminals, browsers, applications, containers, activities, devices, and artifacts.

### Activity

An independently addressable operation with inputs, outputs, progress, events, dependencies, node placement, resource usage, and recovery state.

Canonical states:

```text
queued
preparing
running
waiting
paused
resuming
completed
failed
cancelled
detached
recovering
```

### Artifact

A durable result worth retaining beyond the activity that created it. Artifacts carry hashes, provenance, environment identity, source references, and a manifest.

### Node

A physical or virtual execution contributor that declares operating system, architecture, storage, tools, facilities, devices, health, load, and capability versions.

### Facility

A stable Ptah contract implemented by one or more engines. Examples: browser, transfer, Git, media, firmware, document, application, device, build, and provenance facilities.

### Session

A recoverable representation of a working world. It references workspace state, object graphs, activity state, terminals, browsers, containers, applications, artifacts, storage locations, and connection references.

## 5. Concurrency model

A workspace may simultaneously host:

- several terminals;
- repository clone and fetch operations;
- segmented downloads and resumable uploads;
- container builds;
- browser sessions;
- document rendering;
- image and video processing;
- application decomposition;
- firmware extraction;
- emulator or device sessions;
- cloud synchronization;
- background databases and services.

No unrelated activity may globally lock the workspace.

Activities may be independent or submitted as dependency graphs. The scheduler handles placement, readiness, progress, backpressure, resource accounting, cancellation, and infrastructure retry. It does not decide whether the caller should have requested the work.

## 6. Object and decomposition model

Every input follows:

```text
Input
Upload · URL · Git · Cloud · Local · Node · Device
  ↓
Landing Object
  ↓
Hash and True-Type Detection
  ↓
Immediate Registration
  ↓
Progressive Decomposition
  ↓
Child Objects and Derivatives
  ↓
Navigable, Searchable Object Graph
```

Decomposition levels:

- **Level 0:** hash, size, true type, basic metadata.
- **Level 1:** fast structure such as members, pages, streams, sections, partitions, or repository tree.
- **Level 2:** usable representations such as text, rendered pages, decompiled source, filesystem views, thumbnails, or proxies.
- **Level 3:** deep analysis such as OCR, recursive payloads, call graphs, firmware internals, symbols, entropy, or frame-level derivatives.

Domain packs implement a common contract:

```text
detect
inventory
decompose
preview
open_or_mount
transform
validate
compare
rebuild_where_supported
execute_through_runtime
```

Initial domain packs:

- Archives
- Documents
- Media
- Executables
- Applications
- Firmware
- Disks and Filesystems
- Source Code
- Databases
- Web
- Unknown Binary Research

## 7. Control and execution planes

### Control plane

Records and exposes:

- projects and workspaces;
- object and artifact catalogue;
- activities and durable histories;
- nodes and capabilities;
- facilities and plugins;
- sessions and checkpoints;
- storage locations and synchronization state;
- events, metrics, logs, and health.

### Execution plane

Runs physical work through providers:

- local processes;
- OCI containers;
- remote Linux hosts;
- Dev Container-compatible workspaces;
- later VMs, Windows, macOS, GPU nodes, emulators, and devices.

A provider implements:

```text
create
start
stop
pause
resume
snapshot
destroy
attach_storage
expose_port
open_terminal
report_capabilities
```

## 8. Storage fabric

Initial storage classes:

- **Hot local storage:** worktrees, caches, builds, containers, browser profiles, media intermediates, mounted filesystems, databases, emulator images.
- **Object storage:** uploaded originals, artifacts, large logs, documents, media, firmware, session archives, screenshots, proof bundles.
- **Metadata catalogue:** objects, relationships, activities, nodes, artifacts, sessions, hashes, locations, and sync state.
- **Git:** source code, versioned documentation, and reviewable configuration.
- **User export and recovery storage:** selected session bundles, documents, and readable backups.

Logical locations use stable Ptah identifiers such as:

```text
ptah://projects/<project>
ptah://workspaces/<workspace>
ptah://objects/<object>
ptah://artifacts/<artifact>
ptah://sources/external/<source>
ptah://cache/<cache>
ptah://volumes/<volume>
ptah://sessions/<session>
```

## 9. Relay, events, and durable work

Ptah separates:

- fast event transport for terminal output, browser events, progress, node health, and artifact notifications;
- durable workflow history for long transfers, builds, decomposition, rendering, checkpoints, and node recovery.

Donor research includes NATS and Temporal, but Ptah owns its event envelope and activity contract.

## 10. Facility strategy

Ptah owns neutral contracts and integration. It does not recreate mature machinery without evidence.

Examples of expected machinery:

- Playwright for browser control;
- containerd and OCI specifications for containers;
- BuildKit and Dagger patterns for builds and typed execution graphs;
- FFmpeg and libvips for media;
- libarchive, Tika, LIEF, Binwalk, JADX, and domain tools for decomposition;
- platform tools, Appium, scrcpy, STF, and device-specific adapters for devices;
- Witness, in-toto, Cosign, ORAS, and related tooling for provenance and artifacts;
- OpenTelemetry for logs, metrics, and traces.

Every donor decision must be recorded as Adopt, Adapt, Wrap, Study Only, Host as Workload, Reject, or Further Inspection Required.

## 11. Public boundary

Public Ptah documentation may describe generic humans, applications, agents, automation clients, facilities, nodes, APIs, and workloads.

It must not expose private company identities, private operation chains, private credentials, customer data, unpublished product relationships, or private deployment topology.

## 12. Future local system integration

Ptah begins online. Later, a local always-on node or appliance may run the same node protocol, workspace contracts, object model, activity model, facilities, and session format.

The online system is not a disposable prototype. The local system extends it.

Operating-system boot, hardware drivers, atomic updates, disk encryption, recovery, and machine lifecycle belong to a later platform-integration lane and do not redefine Ptah’s public core.
