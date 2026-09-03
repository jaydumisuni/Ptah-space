//! D08 provider-neutral Application compatibility and remote-Node dependency truth.

use crate::D08Error;
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;
use serde::{Deserialize, Serialize};

/// Roadmap platform class evaluated by D08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformClass {
    /// Linux application executed directly on a capable Node.
    LinuxNative,
    /// Linux packaged application executed on a capable Node.
    LinuxPackaged,
    /// Android application controlled by the existing C10 Device/Application runtime.
    Android,
    /// Windows application requiring a Windows Node.
    WindowsNode,
    /// Windows application requiring a virtual-machine-capable Node.
    WindowsVm,
    /// macOS application requiring a macOS Node.
    MacOsNode,
    /// iOS Simulator application requiring a compatible macOS/Xcode Simulator Node.
    IosSimulator,
}

/// Frozen Application compatibility operation vocabulary used by D08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationOperation {
    /// Install an Application Revision.
    Install,
    /// Upgrade an installation.
    Upgrade,
    /// Repair an installation.
    Repair,
    /// Uninstall an application.
    Uninstall,
    /// Launch without a graphical display requirement.
    LaunchHeadless,
    /// Launch with graphical readiness requirements.
    LaunchGraphical,
    /// Expose a remote application display.
    RemoteDisplay,
    /// Inspect semantic application state.
    SemanticInspection,
    /// Control an application through semantic state.
    SemanticControl,
    /// Control an application through visual input.
    VisualControl,
    /// Capture an application checkpoint.
    Checkpoint,
    /// Restore an application checkpoint.
    Restore,
}

/// Frozen top-level compatibility decision vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityDecision {
    /// All mandatory requirements are satisfied.
    Compatible,
    /// Requirements are satisfied only under explicit retained conditions.
    CompatibleWithConditions,
    /// Only an explicitly bounded operation scope is compatible.
    CompatibleForPartialScope,
    /// Requirements prove the application incompatible.
    Incompatible,
    /// The Provider does not support this operation/platform combination.
    Unsupported,
    /// A required dependency is absent.
    MissingDependency,
    /// A required capability is absent.
    MissingCapability,
    /// Resource or policy evidence blocks the operation.
    ResourceOrPolicyBlocked,
    /// Evidence is insufficient to decide compatibility.
    Unknown,
    /// The compatibility evidence is no longer current.
    Stale,
}

/// Frozen per-requirement outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementOutcome {
    /// Requirement is satisfied.
    Satisfied,
    /// Requirement is satisfied only under explicit conditions.
    SatisfiedWithConditions,
    /// Requirement is proven unsatisfied.
    Unsatisfied,
    /// Provider/platform does not support the requirement.
    Unsupported,
    /// Evidence is insufficient to evaluate the requirement.
    Unknown,
    /// Requirement evidence is stale.
    Stale,
}

/// One evidence-backed compatibility requirement result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityRequirement {
    /// Stable requirement key.
    pub key: String,
    /// Whether this requirement must be satisfied for a compatible decision.
    pub mandatory: bool,
    /// Mechanical result for this requirement.
    pub outcome: RequirementOutcome,
    /// Conditions constraining a conditional success.
    pub condition_refs: Vec<EntityRef>,
    /// Evidence supporting this requirement result.
    pub evidence_refs: Vec<EntityRef>,
    /// Optional bounded explanation retained with the result.
    pub reason: Option<String>,
}

/// Exact current compatibility evidence for a Node-local Application Revision operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLocalCompatibility {
    /// Stable compatibility-record identity.
    pub compatibility_ref: EntityRef,
    /// Exact Application Revision evaluated.
    pub application_revision_ref: EntityRef,
    /// Exact operation evaluated.
    pub operation: ApplicationOperation,
    /// Exact Provider Revision used for the evaluation.
    pub provider_revision_ref: EntityRef,
    /// Exact Provider Instance used for the evaluation.
    pub provider_instance_ref: EntityRef,
    /// Provider generation bound to the evidence.
    pub provider_generation: ProviderGeneration,
    /// Exact Node evaluated.
    pub node_ref: EntityRef,
    /// Node generation bound to the evidence.
    pub node_generation: u64,
    /// Capability snapshot used for evaluation.
    pub node_capability_snapshot_ref: EntityRef,
    /// Resource snapshot used for evaluation.
    pub node_resource_snapshot_ref: EntityRef,
    /// Individual requirement results.
    pub requirements: Vec<CompatibilityRequirement>,
    /// Top-level compatibility decision.
    pub decision: CompatibilityDecision,
    /// Conditions applying to the top-level decision.
    pub condition_refs: Vec<EntityRef>,
    /// Evaluation timestamp.
    pub evaluated_at: String,
    /// Expiry timestamp after which this record cannot admit new work.
    pub valid_until: String,
    /// Evidence supporting the evaluation as a whole.
    pub evidence_refs: Vec<EntityRef>,
    /// Explicit bounded limitations.
    pub limitations: Vec<String>,
}

impl NodeLocalCompatibility {
    /// Validate this compatibility record at a strict UTC observation time.
    ///
    /// # Errors
    /// Returns [`D08Error`] when required evidence is absent, time bounds are invalid/stale,
    /// conditions are missing, or mandatory requirement truth contradicts compatibility.
    pub fn validate_at(&self, now: &str) -> Result<(), D08Error> {
        if self.evidence_refs.is_empty()
            || self.requirements.is_empty()
            || self.node_generation == 0
        {
            return Err(D08Error::MissingCompatibilityEvidence);
        }
        if self
            .requirements
            .iter()
            .any(|requirement| requirement.evidence_refs.is_empty())
        {
            return Err(D08Error::MissingCompatibilityEvidence);
        }

        let evaluated_at =
            parse_utc_datetime(&self.evaluated_at).ok_or(D08Error::InvalidTimestamp)?;
        let valid_until =
            parse_utc_datetime(&self.valid_until).ok_or(D08Error::InvalidTimestamp)?;
        let now = parse_utc_datetime(now).ok_or(D08Error::InvalidTimestamp)?;
        if evaluated_at > now || valid_until <= now || valid_until <= evaluated_at {
            return Err(D08Error::StaleCompatibility);
        }

        if matches!(self.decision, CompatibilityDecision::Stale) {
            return Err(D08Error::StaleCompatibility);
        }

        let compatible_decision = matches!(
            self.decision,
            CompatibilityDecision::Compatible
                | CompatibilityDecision::CompatibleWithConditions
                | CompatibilityDecision::CompatibleForPartialScope
        );
        if compatible_decision
            && self.requirements.iter().any(|requirement| {
                requirement.mandatory
                    && matches!(
                        requirement.outcome,
                        RequirementOutcome::Unsatisfied
                            | RequirementOutcome::Unsupported
                            | RequirementOutcome::Unknown
                            | RequirementOutcome::Stale
                    )
            })
        {
            return Err(D08Error::MandatoryRequirementUnsatisfied);
        }

        if matches!(
            self.decision,
            CompatibilityDecision::CompatibleWithConditions
        ) && (self.condition_refs.is_empty()
            || self.requirements.iter().any(|requirement| {
                requirement.mandatory
                    && matches!(
                        requirement.outcome,
                        RequirementOutcome::SatisfiedWithConditions
                    )
                    && requirement.condition_refs.is_empty()
            }))
        {
            return Err(D08Error::MissingCompatibilityConditions);
        }

        Ok(())
    }
}

/// Evidence explaining why a roadmap platform cannot execute before Programme E remote Nodes exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteNodeRequirement {
    /// Platform that needs remote execution authority.
    pub platform: PlatformClass,
    /// Requested Application operation.
    pub operation: ApplicationOperation,
    /// Required remote execution class.
    pub required_execution_class: String,
    /// Mechanical capability classes that a future Node must prove.
    pub required_capabilities: Vec<String>,
    /// Roadmap dependency that must be satisfied before re-evaluation.
    pub roadmap_dependency: String,
    /// Evidence supporting the dependency/blocker projection.
    pub evidence_refs: Vec<EntityRef>,
    /// Explicit limitations retained with the blocker.
    pub limitations: Vec<String>,
}

/// Current D08 disposition for an Application/platform operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionDisposition {
    /// Exact current local compatibility permits Node-local execution admission.
    NodeLocalReady(NodeLocalCompatibility),
    /// Device-local execution is owned by an existing Device runtime such as C10.
    DeviceLocalReady,
    /// Execution cannot be admitted until Programme E supplies a compatible remote Node.
    RequiresRemoteNode(RemoteNodeRequirement),
    /// The current provider/platform explicitly does not support the operation.
    Unsupported,
    /// Current evidence is insufficient to choose an executable disposition.
    Unknown,
}

impl ExecutionDisposition {
    /// Evaluate the current D08 execution disposition without manufacturing remote authority.
    ///
    /// # Errors
    /// Returns [`D08Error`] when supplied local compatibility is absent, stale, or covers another
    /// operation, or when blocker evidence required for a remote-node projection is absent.
    pub fn for_platform(
        platform: PlatformClass,
        operation: ApplicationOperation,
        compatibility: Option<NodeLocalCompatibility>,
        evidence_refs: Vec<EntityRef>,
        now: &str,
    ) -> Result<Self, D08Error> {
        match platform {
            PlatformClass::LinuxNative | PlatformClass::LinuxPackaged => {
                let compatibility = compatibility.ok_or(D08Error::MissingNodeLocalCompatibility)?;
                if compatibility.operation != operation {
                    return Err(D08Error::CompatibilityOperationMismatch);
                }
                compatibility.validate_at(now)?;
                Ok(Self::NodeLocalReady(compatibility))
            }
            PlatformClass::Android => Ok(Self::Unknown),
            PlatformClass::WindowsNode
            | PlatformClass::WindowsVm
            | PlatformClass::MacOsNode
            | PlatformClass::IosSimulator => {
                if evidence_refs.is_empty() {
                    return Err(D08Error::MissingCompatibilityEvidence);
                }
                Ok(Self::RequiresRemoteNode(remote_requirement(
                    platform,
                    operation,
                    evidence_refs,
                )))
            }
        }
    }

    /// Borrow exact node-local compatibility or fail closed for every non-local disposition.
    ///
    /// # Errors
    /// Returns [`D08Error::RemoteNodeRequired`] for a remote dependency and
    /// [`D08Error::MissingNodeLocalCompatibility`] for every other non-local disposition.
    pub const fn require_node_local(&self) -> Result<&NodeLocalCompatibility, D08Error> {
        match self {
            Self::NodeLocalReady(compatibility) => Ok(compatibility),
            Self::RequiresRemoteNode(_) => Err(D08Error::RemoteNodeRequired),
            Self::DeviceLocalReady | Self::Unsupported | Self::Unknown => {
                Err(D08Error::MissingNodeLocalCompatibility)
            }
        }
    }
}

fn remote_requirement(
    platform: PlatformClass,
    operation: ApplicationOperation,
    evidence_refs: Vec<EntityRef>,
) -> RemoteNodeRequirement {
    let (required_execution_class, required_capabilities): (&str, &[&str]) = match platform {
        PlatformClass::WindowsNode => (
            "windows_node",
            &["windows", "remote_node", "graphical_display"],
        ),
        PlatformClass::WindowsVm => (
            "windows_vm",
            &[
                "windows",
                "virtualization",
                "remote_node",
                "graphical_display",
            ],
        ),
        PlatformClass::MacOsNode => ("macos_node", &["macos", "remote_node", "graphical_display"]),
        PlatformClass::IosSimulator => (
            "ios_simulator",
            &[
                "macos",
                "xcode_simulator",
                "graphical_display",
                "remote_node",
            ],
        ),
        PlatformClass::LinuxNative | PlatformClass::LinuxPackaged | PlatformClass::Android => {
            unreachable!("remote requirement is only created for remote roadmap platforms")
        }
    };
    RemoteNodeRequirement {
        platform,
        operation,
        required_execution_class: String::from(required_execution_class),
        required_capabilities: required_capabilities
            .iter()
            .map(|value| String::from(*value))
            .collect(),
        roadmap_dependency: String::from("Programme E"),
        evidence_refs,
        limitations: vec![String::from(
            "D08 records compatibility/dependency truth only; it does not allocate a remote Node, Provider, lease, fence, remote service, Application Session, or Display Session",
        )],
    }
}

fn parse_utc_datetime(value: &str) -> Option<(u16, u8, u8, u8, u8, u8, u32)> {
    let body = value.strip_suffix('Z')?;
    let (whole, nanos) = match body.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty()
                || fraction.len() > 9
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let mut padded = String::from(fraction);
            padded.extend(std::iter::repeat_n('0', 9 - fraction.len()));
            (whole, padded.parse().ok()?)
        }
        None => (body, 0),
    };
    if whole.len() != 19
        || whole.as_bytes().get(4) != Some(&b'-')
        || whole.as_bytes().get(7) != Some(&b'-')
        || whole.as_bytes().get(10) != Some(&b'T')
        || whole.as_bytes().get(13) != Some(&b':')
        || whole.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }
    let year = whole.get(0..4)?.parse().ok()?;
    let month = whole.get(5..7)?.parse().ok()?;
    let day = whole.get(8..10)?.parse().ok()?;
    let hour = whole.get(11..13)?.parse().ok()?;
    let minute = whole.get(14..16)?.parse().ok()?;
    let second = whole.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some((year, month, day, hour, minute, second, nanos))
}
