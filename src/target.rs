use anyhow::{anyhow, bail, Context, Result};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec {
    label: String,
    hosts: Vec<Ipv4Addr>,
}

impl TargetSpec {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            bail!("target cannot be empty");
        }

        if input.contains('/') {
            return parse_cidr(input);
        }

        if input.contains('-') {
            return parse_range(input);
        }

        parse_single_host(input)
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn hosts(&self) -> &[Ipv4Addr] {
        &self.hosts
    }
}

fn parse_cidr(input: &str) -> Result<TargetSpec> {
    let network =
        Ipv4Net::from_str(input).with_context(|| format!("invalid CIDR target: {input}"))?;
    let hosts = match network.prefix_len() {
        32 => vec![network.addr()],
        31 => vec![network.network(), network.broadcast()],
        _ => network.hosts().collect(),
    };

    if hosts.is_empty() {
        bail!("target {input} does not contain any usable host addresses");
    }

    Ok(TargetSpec {
        label: input.to_string(),
        hosts,
    })
}

fn parse_range(input: &str) -> Result<TargetSpec> {
    let (start, end) = input
        .split_once('-')
        .ok_or_else(|| anyhow!("invalid range target: {input}"))?;

    let start = parse_ipv4(start.trim(), "range start")?;
    let end = parse_ipv4(end.trim(), "range end")?;
    let start_num = u32::from(start);
    let end_num = u32::from(end);

    if start_num > end_num {
        bail!("range start must be less than or equal to range end");
    }

    let host_count = end_num - start_num + 1;
    if host_count > 65_536 {
        bail!("range is too large; split it into smaller scans");
    }

    Ok(TargetSpec {
        label: input.to_string(),
        hosts: (start_num..=end_num).map(Ipv4Addr::from).collect(),
    })
}

fn parse_single_host(input: &str) -> Result<TargetSpec> {
    let host = parse_ipv4(input, "host")?;
    Ok(TargetSpec {
        label: input.to_string(),
        hosts: vec![host],
    })
}

fn parse_ipv4(value: &str, kind: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(value).with_context(|| format!("invalid {kind}: {value}"))
}
