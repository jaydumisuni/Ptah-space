#![forbid(unsafe_code)]
//! E01 thin Node-side secure-link client over the canonical A02 Node agent identity.

use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    HelloAck, LinkError, LinkMessage, NodeHello, ProtocolVersion, TlsClientConfig, connect_tls,
    read_frame, write_frame,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Deployment-provided connection facts for one E01 Node-link attempt.
#[derive(Clone, Debug)]
pub struct NodeLinkClientConfig {
    endpoint: SocketAddr,
    server_name: String,
    tls: TlsClientConfig,
    enrollment_ref: EntityRef,
    agent_revision: String,
    protocol: ProtocolVersion,
}

impl NodeLinkClientConfig {
    /// Construct one Node-link client configuration without changing canonical Node identity.
    #[must_use]
    pub fn new(
        endpoint: SocketAddr,
        server_name: String,
        tls: TlsClientConfig,
        enrollment_ref: EntityRef,
        agent_revision: String,
        protocol: ProtocolVersion,
    ) -> Self {
        Self {
            endpoint,
            server_name,
            tls,
            enrollment_ref,
            agent_revision,
            protocol,
        }
    }

    fn hello(&self, agent: &NodeAgent) -> NodeHello {
        NodeHello {
            supported_major: self.protocol.major,
            minimum_minor: self.protocol.minor,
            maximum_minor: self.protocol.minor,
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            enrollment_ref: self.enrollment_ref.clone(),
            agent_revision: self.agent_revision.clone(),
            capability_snapshot_ref: None,
        }
    }
}

/// Connect one Node to the E01 control plane, send its current A02 identity, and accept a matching hello acknowledgement.
///
/// This helper does not mutate Node Generation/epoch, persist capability truth,
/// or implement scheduling/placement/transfer semantics.
///
/// # Errors
///
/// Returns an E01 [`LinkError`] for TCP/TLS/framing failures, incompatible
/// protocol selection, or any acknowledgement that does not match the exact
/// Node identity, Generation, and epoch sent in the hello.
pub async fn run_node_link_client(
    agent: &NodeAgent,
    config: &NodeLinkClientConfig,
) -> Result<HelloAck, LinkError> {
    let tcp = TcpStream::connect(config.endpoint).await?;
    let mut tls = connect_tls(tcp, &config.server_name, &config.tls).await?;
    let hello = config.hello(agent);
    write_frame(
        tls.stream_mut(),
        &LinkMessage::Hello(Box::new(hello.clone())),
    )
    .await?;

    let LinkMessage::HelloAck(ack) = read_frame(tls.stream_mut()).await? else {
        return Err(LinkError::MalformedFrame(String::from(
            "expected hello_ack after node hello",
        )));
    };

    if ack.selected_version.major != config.protocol.major {
        return Err(LinkError::ProtocolIncompatible {
            local_major: config.protocol.major,
            remote_major: ack.selected_version.major,
        });
    }
    if ack.selected_version.minor != config.protocol.minor {
        return Err(LinkError::ProtocolMinorIncompatible {
            local_minor: config.protocol.minor,
            remote_min: ack.selected_version.minor,
            remote_max: ack.selected_version.minor,
        });
    }
    if ack.node_id != hello.node_id {
        return Err(LinkError::NodeIdentityMismatch);
    }
    if ack.node_generation != hello.node_generation {
        return Err(LinkError::StaleNodeGeneration {
            current: hello.node_generation.value(),
            requested: ack.node_generation.value(),
        });
    }
    if ack.connection_epoch != hello.connection_epoch {
        return Err(LinkError::StaleConnectionEpoch {
            current: hello.connection_epoch.value(),
            requested: ack.connection_epoch.value(),
        });
    }
    Ok(ack)
}
