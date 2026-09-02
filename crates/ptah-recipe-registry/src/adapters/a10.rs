use crate::{
    ContainerAuthorityScope, ContainerMountAccess, ContainerMountScope, ContainerNetworkScope,
};
use container_oci::{MountAccess, MountRequest, NetworkPolicy};

fn project_authority(network: &NetworkPolicy, mounts: &[MountRequest]) -> ContainerAuthorityScope {
    let network = match network {
        NetworkPolicy::Isolated => ContainerNetworkScope::Isolated,
        NetworkPolicy::Host { grant_ref } => ContainerNetworkScope::Host {
            grant_ref: grant_ref.clone(),
        },
    };
    let mounts = mounts
        .iter()
        .map(|mount| ContainerMountScope {
            source_alias: mount.source_alias.clone(),
            destination: mount.destination.clone(),
            access: match mount.access {
                MountAccess::ReadOnly => ContainerMountAccess::ReadOnly,
                MountAccess::ReadWrite => ContainerMountAccess::ReadWrite,
            },
            grant_ref: mount.grant_ref.clone(),
        })
        .collect();
    ContainerAuthorityScope { network, mounts }
}

pub(crate) fn normalize_authority(scope: &ContainerAuthorityScope) -> ContainerAuthorityScope {
    let network = match &scope.network {
        ContainerNetworkScope::Isolated => NetworkPolicy::Isolated,
        ContainerNetworkScope::Host { grant_ref } => NetworkPolicy::Host {
            grant_ref: grant_ref.clone(),
        },
    };
    let mounts = scope
        .mounts
        .iter()
        .map(|mount| MountRequest {
            source_alias: mount.source_alias.clone(),
            destination: mount.destination.clone(),
            access: match mount.access {
                ContainerMountAccess::ReadOnly => MountAccess::ReadOnly,
                ContainerMountAccess::ReadWrite => MountAccess::ReadWrite,
            },
            grant_ref: mount.grant_ref.clone(),
        })
        .collect::<Vec<_>>();
    project_authority(&network, &mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{D04Error, validate_container_authority};
    use ptah_identifiers::EntityRef;

    #[test]
    fn actual_a10_projection_cannot_widen_grants() {
        let network_grant = EntityRef::new("isolation.network_exposure_grant").unwrap();
        let mount_grant = EntityRef::new("isolation.filesystem_access_grant").unwrap();
        let network = NetworkPolicy::Host {
            grant_ref: network_grant,
        };
        let mounts = vec![MountRequest {
            source_alias: "/srv/input".to_owned(),
            destination: "/input".to_owned(),
            access: MountAccess::ReadOnly,
            grant_ref: mount_grant,
        }];
        let baseline = project_authority(&network, &mounts);
        let widened = project_authority(
            &NetworkPolicy::Host {
                grant_ref: EntityRef::new("isolation.network_exposure_grant").unwrap(),
            },
            &mounts,
        );
        assert!(matches!(
            validate_container_authority(&baseline, &widened),
            Err(D04Error::AuthorityWidening { .. })
        ));
    }
}
