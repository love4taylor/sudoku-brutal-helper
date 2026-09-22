use anyhow::{Context, Result, bail};
use libc::{AF_INET, AF_INET6, AF_NETLINK, IPPROTO_TCP, NETLINK_ROUTE, NETLINK_SOCK_DIAG};
use log::{info, warn};
use std::collections::HashSet;
use std::fs::{OpenOptions, read_to_string};
use std::io::Write;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::time::Duration;

const BRUTAL_RULES: &str = "/proc/net/tcp_brutal/rules";
const BRUTAL_ROUTE_PROTOCOL: u8 = 233;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const TCP_ESTABLISHED: u8 = 1;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_METRICS: u16 = 8;
const RTAX_LOCK: u16 = 1;
const RTAX_CC_ALGO: u16 = 16;
const RT_TABLE_MAIN: u8 = 254;
const RTN_UNICAST: u8 = 1;
const RT_SCOPE_UNIVERSE: u8 = 0;

pub struct NativeRunner {
    rate_mbps: u64,
    timeout: Duration,
    dry_run: bool,
}

impl NativeRunner {
    pub fn new(settings: &crate::config::Settings, dry_run: bool) -> Self {
        Self {
            rate_mbps: settings.rate_mbps,
            timeout: Duration::from_secs(settings.operation_timeout_seconds),
            dry_run,
        }
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    pub fn scan_clients(&self, listen_port: u16) -> Result<Vec<IpAddr>> {
        let mut seen = HashSet::new();
        let mut clients = Vec::new();
        for family in [AF_INET as u8, AF_INET6 as u8] {
            for socket in diag_dump(family, listen_port, None, self.timeout)? {
                let peer = normalize_ip(socket.peer);
                if seen.insert(peer) {
                    clients.push(peer);
                }
            }
        }
        clients.sort_by_key(ToString::to_string);
        Ok(clients)
    }

    pub fn add(&self, ip: IpAddr) -> Result<()> {
        let prefix = client_prefix(ip);
        let rate_bytes_per_second: u64 = (self.rate_mbps as u128 * 1_000_000 / 8)
            .try_into()
            .context("rate_mbps exceeds the supported Brutal range")?;
        if self.dry_run {
            info!("[dry-run] add Brutal rule: add {prefix} rate={rate_bytes_per_second}");
            return Ok(());
        }
        write_rule(&format!("add {prefix} rate={rate_bytes_per_second}\n"))?;
        if let Err(error) = route_replace(ip) {
            let _ = write_rule(&format!("del {prefix}\n"));
            return Err(error).context("failed to install the Brutal route; rule rolled back");
        }
        Ok(())
    }

    pub fn delete(&self, ip: IpAddr) -> Result<bool> {
        let prefix = client_prefix(ip);
        if self.dry_run {
            info!("[dry-run] delete Brutal rule: del {prefix}");
            return Ok(true);
        }
        match write_rule(&format!("del {prefix}\n")) {
            Ok(()) => {
                if let Err(error) = route_delete(ip) {
                    warn!(
                        "failed to delete the Brutal route for {}; continuing: {error:#}",
                        prefix
                    );
                }
                Ok(true)
            }
            Err(error) => {
                warn!("failed to delete Brutal rule {prefix}: {error:#}");
                Ok(false)
            }
        }
    }

    pub fn disconnect(&self, ip: IpAddr, listen_port: u16) -> Result<bool> {
        if self.dry_run {
            let mut count = 0;
            for family in [AF_INET as u8, AF_INET6 as u8] {
                count += diag_dump(family, listen_port, Some(ip), self.timeout)?.len();
            }
            info!(
                "[dry-run] would destroy {} TCP connection(s) through sock_diag (peer_ip={}, local_port={})",
                count, ip, listen_port
            );
            return Ok(count > 0);
        }
        let mut disconnected = false;
        for family in [AF_INET as u8, AF_INET6 as u8] {
            for socket in diag_dump(family, listen_port, Some(ip), self.timeout)? {
                destroy_socket(family, socket, self.timeout)?;
                disconnected = true;
            }
        }
        Ok(disconnected)
    }
}

#[derive(Clone, Copy, Debug)]
struct SocketIdentity {
    local: IpAddr,
    peer: IpAddr,
    local_port: u16,
    peer_port: u16,
    cookie: [u32; 2],
}

fn write_rule(command: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(BRUTAL_RULES)
        .with_context(|| format!("cannot open {BRUTAL_RULES}; is tcp-brutal 2.x loaded?"))?;
    file.write_all(command.as_bytes())
        .with_context(|| format!("failed to write Brutal rule: {}", command.trim()))?;
    Ok(())
}

pub fn client_prefix(ip: IpAddr) -> String {
    format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
    }
}

fn diag_dump(
    family: u8,
    local_port: u16,
    peer_filter: Option<IpAddr>,
    timeout: Duration,
) -> Result<Vec<SocketIdentity>> {
    let mut request = vec![0u8; 16 + 56];
    put_nl_header(
        &mut request,
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        1,
    );
    request[16] = family;
    request[17] = IPPROTO_TCP as u8;
    request[20..24].copy_from_slice(&(1u32 << TCP_ESTABLISHED).to_ne_bytes());
    let socket = NetlinkSocket::open(NETLINK_SOCK_DIAG, timeout)?;
    socket.send(&request)?;
    let mut result = Vec::new();
    for message in socket.receive_messages()? {
        if message.kind == NLMSG_DONE {
            break;
        }
        if message.kind == NLMSG_ERROR {
            return Err(netlink_error(&message.payload));
        }
        if message.payload.len() < 84 {
            continue;
        }
        let payload = &message.payload;
        if payload[0] != family || payload[1] != TCP_ESTABLISHED {
            continue;
        }
        let identity = decode_socket_identity(payload, family)?;
        if identity.local_port != local_port {
            continue;
        }
        if peer_filter.is_some_and(|peer| normalize_ip(identity.peer) != normalize_ip(peer)) {
            continue;
        }
        result.push(identity);
    }
    Ok(result)
}

fn destroy_socket(family: u8, socket: SocketIdentity, timeout: Duration) -> Result<()> {
    let mut request = vec![0u8; 16 + 56];
    put_nl_header(&mut request, SOCK_DESTROY, NLM_F_REQUEST | NLM_F_ACK, 1);
    request[16] = family;
    request[17] = IPPROTO_TCP as u8;
    request[24..26].copy_from_slice(&socket.local_port.to_be_bytes());
    request[26..28].copy_from_slice(&socket.peer_port.to_be_bytes());
    encode_ip(family, socket.local, &mut request[28..44])?;
    encode_ip(family, socket.peer, &mut request[44..60])?;
    request[64..68].copy_from_slice(&socket.cookie[0].to_ne_bytes());
    request[68..72].copy_from_slice(&socket.cookie[1].to_ne_bytes());
    let netlink = NetlinkSocket::open(NETLINK_SOCK_DIAG, timeout)?;
    netlink.send(&request)?;
    for message in netlink.receive_messages()? {
        if message.kind == NLMSG_ERROR {
            if message.payload.len() < 4 {
                bail!("sock_diag returned an invalid error");
            }
            let error = i32::from_ne_bytes(message.payload[0..4].try_into().unwrap());
            if error == 0 {
                return Ok(());
            }
            return Err(std::io::Error::from_raw_os_error(-error).into());
        }
    }
    Ok(())
}

fn decode_socket_identity(payload: &[u8], family: u8) -> Result<SocketIdentity> {
    let local_port = u16::from_be_bytes(payload[4..6].try_into().unwrap());
    let peer_port = u16::from_be_bytes(payload[6..8].try_into().unwrap());
    let local = decode_ip(family, &payload[8..24])?;
    let peer = decode_ip(family, &payload[24..40])?;
    let cookie = [
        u32::from_ne_bytes(payload[44..48].try_into().unwrap()),
        u32::from_ne_bytes(payload[48..52].try_into().unwrap()),
    ];
    Ok(SocketIdentity {
        local,
        peer,
        local_port,
        peer_port,
        cookie,
    })
}

fn decode_ip(family: u8, bytes: &[u8]) -> Result<IpAddr> {
    match family as i32 {
        AF_INET => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[..16]).unwrap(),
        ))),
        _ => bail!("unsupported socket address family {family}"),
    }
}

fn encode_ip(family: u8, ip: IpAddr, output: &mut [u8]) -> Result<()> {
    match (family as i32, ip) {
        (AF_INET, IpAddr::V4(ip)) => output[..4].copy_from_slice(&ip.octets()),
        (AF_INET6, IpAddr::V6(ip)) => output[..16].copy_from_slice(&ip.octets()),
        _ => bail!("socket address family does not match the IP type"),
    }
    Ok(())
}

fn put_nl_header(buffer: &mut [u8], kind: u16, flags: u16, sequence: u32) {
    let length = buffer.len() as u32;
    buffer[0..4].copy_from_slice(&length.to_ne_bytes());
    buffer[4..6].copy_from_slice(&kind.to_ne_bytes());
    buffer[6..8].copy_from_slice(&flags.to_ne_bytes());
    buffer[8..12].copy_from_slice(&sequence.to_ne_bytes());
    buffer[12..16].copy_from_slice(&0u32.to_ne_bytes());
}

struct NetlinkMessage {
    kind: u16,
    payload: Vec<u8>,
}

struct NetlinkSocket {
    fd: RawFd,
}

impl NetlinkSocket {
    fn open(protocol: i32, timeout: Duration) -> Result<Self> {
        let fd = unsafe { libc::socket(AF_NETLINK, libc::SOCK_RAW, protocol) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create netlink socket");
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = AF_NETLINK as u16;
        let result = unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if result < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::last_os_error()).context("failed to bind netlink socket");
        }
        let timeval = libc::timeval {
            tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
            tv_usec: timeout.subsec_micros().into(),
        };
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeval as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as u32,
            )
        };
        if result < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::last_os_error()).context("failed to set netlink timeout");
        }
        Ok(Self { fd })
    }

    fn send(&self, message: &[u8]) -> Result<()> {
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd,
                message.as_ptr().cast(),
                message.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to send netlink request");
        }
        Ok(())
    }

    fn receive_messages(&self) -> Result<Vec<NetlinkMessage>> {
        let mut messages = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let received =
                unsafe { libc::recv(self.fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if received < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to read netlink response");
            }
            if received == 0 {
                break;
            }
            let mut offset = 0usize;
            while offset + 16 <= received as usize {
                let length =
                    u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
                if length < 16 || offset + length > received as usize {
                    bail!("netlink returned an invalid message length");
                }
                let kind = u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into().unwrap());
                messages.push(NetlinkMessage {
                    kind,
                    payload: buffer[offset + 16..offset + length].to_vec(),
                });
                offset += (length + 3) & !3;
                if kind == NLMSG_DONE || kind == NLMSG_ERROR {
                    return Ok(messages);
                }
            }
        }
        Ok(messages)
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn netlink_error(payload: &[u8]) -> anyhow::Error {
    if payload.len() >= 4 {
        let error = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
        return std::io::Error::from_raw_os_error(-error).into();
    }
    anyhow::anyhow!("netlink returned an invalid error")
}

fn route_replace(ip: IpAddr) -> Result<()> {
    let route = route_lookup(ip)?;
    if route.local {
        bail!("destination {ip} is a local address");
    }
    let mut payload = vec![0u8; 12];
    payload[0] = ip_family(ip);
    payload[1] = prefix_len(ip);
    payload[4] = RT_TABLE_MAIN;
    payload[5] = BRUTAL_ROUTE_PROTOCOL;
    payload[6] = RT_SCOPE_UNIVERSE;
    payload[7] = RTN_UNICAST;
    append_attr(&mut payload, RTA_DST, &ip_bytes(ip));
    if let Some(gateway) = route.gateway {
        append_attr(&mut payload, RTA_GATEWAY, &ip_bytes(gateway));
    }
    append_attr(&mut payload, RTA_OIF, &route.interface.to_ne_bytes());
    let mut metrics = Vec::new();
    append_attr(
        &mut metrics,
        RTAX_LOCK,
        &(1u32 << RTAX_CC_ALGO).to_ne_bytes(),
    );
    append_attr(&mut metrics, RTAX_CC_ALGO, b"brutal\0");
    append_attr(&mut payload, RTA_METRICS, &metrics);
    route_request(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | 0x100,
        payload,
    )
}

fn route_delete(ip: IpAddr) -> Result<()> {
    let mut payload = vec![0u8; 12];
    payload[0] = ip_family(ip);
    payload[1] = prefix_len(ip);
    payload[4] = RT_TABLE_MAIN;
    payload[5] = BRUTAL_ROUTE_PROTOCOL;
    payload[7] = RTN_UNICAST;
    append_attr(&mut payload, RTA_DST, &ip_bytes(ip));
    route_request(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, payload)
}

struct RouteLookup {
    gateway: Option<IpAddr>,
    interface: u32,
    local: bool,
}

fn route_lookup(ip: IpAddr) -> Result<RouteLookup> {
    match ip {
        IpAddr::V4(ip) => route_lookup_ipv4(ip),
        IpAddr::V6(ip) => route_lookup_ipv6(ip),
    }
}

fn route_lookup_ipv4(ip: Ipv4Addr) -> Result<RouteLookup> {
    let target = u32::from_be_bytes(ip.octets());
    let mut best: Option<(Option<Ipv4Addr>, u32, u32, u32)> = None;
    let contents = read_to_string("/proc/net/route").context("failed to read /proc/net/route")?;
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let destination = proc_ipv4_value(fields[1]).context("invalid IPv4 route destination")?;
        let gateway_raw =
            u32::from_str_radix(fields[2], 16).context("invalid IPv4 route gateway")?;
        let gateway_value = proc_ipv4_value(fields[2]).context("invalid IPv4 route gateway")?;
        let mask = proc_ipv4_value(fields[7]).context("invalid IPv4 route mask")?;
        if target & mask != destination {
            continue;
        }
        let prefix_len = mask.count_ones();
        let metric = fields
            .get(6)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        let replace = best.is_none_or(|(_, _, best_prefix, best_metric)| {
            prefix_len > best_prefix || (prefix_len == best_prefix && metric < best_metric)
        });
        if replace {
            let gateway = (gateway_value != 0).then(|| Ipv4Addr::from(gateway_raw.to_le_bytes()));
            let interface = unsafe {
                libc::if_nametoindex(std::ffi::CString::new(fields[0]).unwrap().as_ptr())
            };
            if interface == 0 {
                continue;
            }
            best = Some((gateway, interface, prefix_len, metric));
        }
    }
    let (gateway, interface, _, _) = best.context("no IPv4 route found")?;
    Ok(RouteLookup {
        gateway: gateway.map(IpAddr::V4),
        interface,
        local: is_local_address(IpAddr::V4(ip)),
    })
}

fn proc_ipv4_value(value: &str) -> Result<u32> {
    let raw = u32::from_str_radix(value, 16)?;
    Ok(u32::from_be_bytes(raw.to_le_bytes()))
}

fn route_lookup_ipv6(ip: Ipv6Addr) -> Result<RouteLookup> {
    let target = ip.octets();
    let mut best: Option<(u8, u32, Option<Ipv6Addr>, u32)> = None;
    let contents =
        read_to_string("/proc/net/ipv6_route").context("failed to read /proc/net/ipv6_route")?;
    for line in contents.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let destination = parse_hex_ip6(fields[0]).context("invalid IPv6 route destination")?;
        let prefix_len = u8::from_str_radix(fields[1], 16).context("invalid IPv6 route prefix")?;
        if prefix_len > 128 || !prefix_matches(target, destination, prefix_len) {
            continue;
        }
        let gateway = parse_hex_ip6(fields[4]).context("invalid IPv6 route gateway")?;
        let metric = u32::from_str_radix(fields[5], 16).unwrap_or(u32::MAX);
        let replace = best.is_none_or(|(best_prefix, best_metric, _, _)| {
            prefix_len > best_prefix || (prefix_len == best_prefix && metric < best_metric)
        });
        if replace {
            let interface = unsafe {
                libc::if_nametoindex(std::ffi::CString::new(fields[9]).unwrap().as_ptr())
            };
            if interface == 0 {
                continue;
            }
            let gateway = (!gateway.is_unspecified()).then_some(gateway);
            best = Some((prefix_len, metric, gateway, interface));
        }
    }
    let (_, _, gateway, interface) = best.context("no IPv6 route found")?;
    Ok(RouteLookup {
        gateway: gateway.map(IpAddr::V6),
        interface,
        local: is_local_address(IpAddr::V6(ip)),
    })
}

fn parse_hex_ip6(value: &str) -> Result<Ipv6Addr> {
    if value.len() != 32 {
        bail!("invalid IPv6 route address length");
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .context("invalid IPv6 route address")?;
    }
    Ok(Ipv6Addr::from(bytes))
}

fn prefix_matches(target: [u8; 16], route: Ipv6Addr, prefix_len: u8) -> bool {
    let route = route.octets();
    let full_bytes = (prefix_len / 8) as usize;
    let remaining = prefix_len % 8;
    target[..full_bytes] == route[..full_bytes]
        && (remaining == 0 || (target[full_bytes] ^ route[full_bytes]) >> (8 - remaining) == 0)
}

fn is_local_address(ip: IpAddr) -> bool {
    let mut addresses = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return false;
    }
    let mut current = addresses;
    let mut found = false;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            if (family == AF_INET || family == AF_INET6)
                && sockaddr_ip(entry.ifa_addr, family).is_some_and(|address| address == ip)
            {
                found = true;
                break;
            }
        }
        current = entry.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(addresses);
    }
    found
}

fn sockaddr_ip(address: *const libc::sockaddr, family: i32) -> Option<IpAddr> {
    if family == AF_INET {
        let address = unsafe { *(address as *const libc::sockaddr_in) };
        Some(IpAddr::V4(Ipv4Addr::from(
            u32::from_be(address.sin_addr.s_addr).to_be_bytes(),
        )))
    } else if family == AF_INET6 {
        let address = unsafe { *(address as *const libc::sockaddr_in6) };
        Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
    } else {
        None
    }
}

fn route_request(kind: u16, flags: u16, payload: Vec<u8>) -> Result<()> {
    let _ = route_request_response(kind, flags, payload)?;
    Ok(())
}

fn route_request_response(kind: u16, flags: u16, payload: Vec<u8>) -> Result<Vec<u8>> {
    let mut request = vec![0u8; 16 + payload.len()];
    put_nl_header(&mut request, kind, flags, 1);
    request[16..].copy_from_slice(&payload);
    let socket = NetlinkSocket::open(NETLINK_ROUTE, Duration::from_secs(15))?;
    socket.send(&request)?;
    for message in socket.receive_messages()? {
        if message.kind == NLMSG_ERROR {
            if message.payload.len() < 4 {
                bail!("route netlink returned an invalid error");
            }
            let error = i32::from_ne_bytes(message.payload[0..4].try_into().unwrap());
            if error == 0 {
                return Ok(Vec::new());
            }
            return Err(std::io::Error::from_raw_os_error(-error).into());
        }
        if message.kind != NLMSG_NOOP {
            return Ok(message.payload);
        }
    }
    bail!("route netlink returned no response")
}

fn append_attr(buffer: &mut Vec<u8>, kind: u16, value: &[u8]) {
    buffer.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(value);
    while buffer.len() % 4 != 0 {
        buffer.push(0);
    }
}

#[cfg(test)]
fn parse_attrs(mut bytes: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut attrs = Vec::new();
    while bytes.len() >= 4 {
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        if length < 4 || length > bytes.len() {
            bail!("route netlink returned an invalid attribute");
        }
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap());
        attrs.push((kind, bytes[4..length].to_vec()));
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    Ok(attrs)
}

fn ip_family(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        AF_INET as u8
    } else {
        AF_INET6 as u8
    }
}
fn prefix_len(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}
fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_host_prefixes() {
        assert_eq!(client_prefix("192.0.2.1".parse().unwrap()), "192.0.2.1/32");
        assert_eq!(
            client_prefix("2001:db8::1".parse().unwrap()),
            "2001:db8::1/128"
        );
    }

    #[test]
    fn appends_aligned_route_attributes() {
        let mut bytes = Vec::new();
        append_attr(&mut bytes, RTA_OIF, &7u32.to_ne_bytes());
        append_attr(&mut bytes, RTA_GATEWAY, &[192, 0, 2, 1]);
        let attrs = parse_attrs(&bytes).unwrap();
        assert_eq!(attrs[0].1, 7u32.to_ne_bytes());
        assert_eq!(attrs[1].1, vec![192, 0, 2, 1]);
    }

    #[test]
    fn decodes_proc_ipv4_values() {
        assert_eq!(
            proc_ipv4_value("FAFA29C1").unwrap(),
            u32::from_be_bytes([193, 41, 250, 250])
        );
        assert_eq!(
            Ipv4Addr::from(u32::from_str_radix("FAFA29C1", 16).unwrap().to_le_bytes()),
            Ipv4Addr::new(193, 41, 250, 250)
        );
    }
}
