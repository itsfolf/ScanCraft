use std::{fs, net::Ipv4Addr, str::FromStr};

use crate::scanner::targets::{Ipv4Range, Ipv4Ranges};

use anyhow::anyhow;
use tracing::error;

pub fn parse_file(input: &str) -> anyhow::Result<Ipv4Ranges> {
    return match fs::metadata(input) {
        Ok(..) => {
            let input = fs::read_to_string(input)?;

            parse(&input)
        }
        Err(e) => {
            error!("Failed to load {}: {}", input, e.to_string());
            Err(anyhow!(
                "Failed to load {}: {}",
                input,
                e.to_string()
            ))
        }
    }
}

fn parse(input: &str) -> anyhow::Result<Ipv4Ranges> {
    let mut ranges = Vec::new();

    for line in input.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // can be either like 0.0.0.0-0.0.0.0 or 0.0.0.0/32

        let is_slash = line.contains('/');
        let is_hypen = line.contains('-');

        if is_slash && is_hypen {
            return Err(anyhow!(
                "Invalid exclude range: {} (cannot contain both - and /)",
                line
            ));
        }

        let range = if is_slash {
            let mut parts = line.split('/');

            let ip = parts.next().unwrap();
            let mask = parts.next().unwrap();

            let mask = 32 - mask.parse::<u8>()?;

            let mask_bits = 2u32.pow(mask as u32) - 1;

            let ip_u32 = u32::from(Ipv4Addr::from_str(ip)?);

            let addr_start = Ipv4Addr::from(ip_u32 & !mask_bits);
            let addr_end = Ipv4Addr::from(ip_u32 | mask_bits);

            Ipv4Range {
                start: addr_start,
                end: addr_end,
            }
        } else if is_hypen {
            let mut parts = line.split('-');

            let ip_start = parts.next().unwrap();
            let ip_end = parts.next().unwrap();

            let ip_start = Ipv4Addr::from_str(ip_start)?;
            let ip_end = Ipv4Addr::from_str(ip_end)?;

            if ip_start > ip_end {
                return Err(anyhow!(
                    "Invalid exclude range: {} (start cannot be greater than end)",
                    line
                ));
            }

            Ipv4Range {
                start: ip_start,
                end: ip_end,
            }
        } else {
            Ipv4Range::single(Ipv4Addr::from_str(line)?)
        };

        ranges.push(range);
    }

    Ok(Ipv4Ranges::new(ranges))
}
