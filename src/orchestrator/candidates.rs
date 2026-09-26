//! Which addresses the SFU advertises as ICE host candidates.
//!
//! The media socket usually binds a wildcard address (`0.0.0.0:10000`), which
//! a remote peer cannot send to. Candidates use, in order of preference:
//! 1. `transport.announced_ips`, when configured;
//! 2. the bind IP, when it is a specific address;
//! 3. the host's interface addresses (loopback only if nothing else exists).
//!
//! The port is always the port the media socket actually bound, so port 0
//! works.

use std::net::{IpAddr, SocketAddr};

use nexus_core::MAX_ANNOUNCED_IPS;
use nexus_transport::ice::gather::MAX_INTERFACES;

/// Most candidate addresses the SFU advertises.
pub const MAX_CANDIDATE_ADDRS: usize = if MAX_ANNOUNCED_IPS > MAX_INTERFACES {
    MAX_ANNOUNCED_IPS
} else {
    MAX_INTERFACES
};

/// Where the candidate addresses came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    /// `transport.announced_ips`.
    Announced,
    /// The specific IP the media socket is bound to.
    BindAddress,
    /// Guessed from the host's interfaces (wildcard bind, nothing announced).
    Interfaces,
}

/// Choose the IPs to advertise. Pure, so it can be tested without a network.
///
/// Returns an empty list only if the bind address is a wildcard and no
/// interface address is known; the caller must treat that as a startup error.
pub fn select_candidate_ips(
    announced: &[IpAddr],
    bind_ip: IpAddr,
    interface_ips: &[Option<IpAddr>],
) -> (Vec<IpAddr>, CandidateSource) {
    assert!(
        announced.len() <= MAX_ANNOUNCED_IPS,
        "announced_ips is validated"
    );

    let (ips, source): (Vec<IpAddr>, _) = if !announced.is_empty() {
        (announced.to_vec(), CandidateSource::Announced)
    } else if !bind_ip.is_unspecified() {
        (vec![bind_ip], CandidateSource::BindAddress)
    } else {
        let usable = interface_ips
            .iter()
            .take(MAX_INTERFACES)
            .flatten()
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .copied()
            // A socket bound to 0.0.0.0 cannot receive on IPv6 addresses.
            .filter(|ip| ip.is_ipv4() == bind_ip.is_ipv4())
            .collect();
        (usable, CandidateSource::Interfaces)
    };

    // Postconditions: never advertise an address nobody can send to.
    assert!(ips.len() <= MAX_CANDIDATE_ADDRS);
    for ip in &ips {
        assert!(!ip.is_unspecified(), "candidate IP must not be unspecified");
        assert!(!ip.is_multicast(), "candidate IP must not be multicast");
    }
    (ips, source)
}

/// Candidate socket addresses for the media socket bound at `bound`.
pub fn candidate_addrs(
    announced: &[IpAddr],
    bound: SocketAddr,
) -> (Vec<SocketAddr>, CandidateSource) {
    assert!(bound.port() != 0, "candidate port must be the bound port");
    let interfaces = if announced.is_empty() && bound.ip().is_unspecified() {
        nexus_transport::ice::gather::host_interface_ips()
    } else {
        [None; MAX_INTERFACES]
    };
    let (ips, source) = select_candidate_ips(announced, bound.ip(), &interfaces);
    let addrs = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, bound.port()))
        .collect();
    (addrs, source)
}

/// Candidate addresses for startup, logged; an error if there are none.
pub fn resolve(announced: &[IpAddr], bound: SocketAddr) -> Result<Vec<SocketAddr>, String> {
    let (addrs, source) = candidate_addrs(announced, bound);
    if addrs.is_empty() {
        return Err(format!(
            "no ICE candidate address: media socket bound to {bound} and no interface \
             address found; set transport.announced_ips or NEXUS_ANNOUNCED_IPS"
        ));
    }
    match source {
        CandidateSource::Interfaces => tracing::warn!(
            "transport.announced_ips is empty and the media socket is bound to {}; \
             advertising interface addresses {:?}. Set NEXUS_ANNOUNCED_IPS to the \
             public address if clients connect through NAT",
            bound,
            addrs
        ),
        _ => tracing::info!("ICE host candidates: {:?}", addrs),
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn announced_ips_win() {
        let announced = [ip("203.0.113.7"), ip("198.51.100.2")];
        let (ips, source) =
            select_candidate_ips(&announced, ip("10.0.0.5"), &[Some(ip("10.0.0.5"))]);
        assert_eq!(ips, announced.to_vec());
        assert_eq!(source, CandidateSource::Announced);
    }

    #[test]
    fn specific_bind_ip_is_used() {
        let (ips, source) = select_candidate_ips(&[], ip("10.0.0.5"), &[Some(ip("192.168.1.2"))]);
        assert_eq!(ips, vec![ip("10.0.0.5")]);
        assert_eq!(source, CandidateSource::BindAddress);
    }

    #[test]
    fn wildcard_bind_falls_back_to_interfaces() {
        let interfaces = [
            Some(ip("192.168.1.2")),
            Some(ip("2001:db8::1")),
            Some(ip("0.0.0.0")),
            Some(ip("10.1.2.3")),
            None,
        ];
        let (ips, source) = select_candidate_ips(&[], ip("0.0.0.0"), &interfaces);
        assert_eq!(ips, vec![ip("192.168.1.2"), ip("10.1.2.3")]);
        assert_eq!(source, CandidateSource::Interfaces);
    }

    #[test]
    fn wildcard_with_no_interfaces_is_empty() {
        let (ips, _) = select_candidate_ips(&[], ip("0.0.0.0"), &[None, None]);
        assert!(ips.is_empty());
    }

    #[test]
    fn never_unspecified_with_real_interfaces() {
        let bound: SocketAddr = "0.0.0.0:10000".parse().unwrap();
        let (addrs, source) = candidate_addrs(&[], bound);
        assert_eq!(source, CandidateSource::Interfaces);
        for addr in addrs {
            assert!(!addr.ip().is_unspecified());
            assert_eq!(addr.port(), 10000);
        }
    }

    #[test]
    fn port_is_the_bound_port() {
        let bound: SocketAddr = "127.0.0.1:43210".parse().unwrap();
        let (addrs, _) = candidate_addrs(&[ip("203.0.113.7")], bound);
        assert_eq!(
            addrs,
            vec!["203.0.113.7:43210".parse::<SocketAddr>().unwrap()]
        );
    }
}
