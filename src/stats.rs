//! Feasibility analysis and run statistics.

/// Estimate how long a scan of `candidates` would take.
/// `checks_per_candidate` is the number of network balance checks per candidate.
/// `rate_per_sec` is the network checks we assume achievable per second.
pub struct Feasibility {
    pub total_checks: u128,
    pub seconds: u64,
}

pub fn feasibility(candidates: u64, checks_per_candidate: u64, rate_per_sec: u64) -> Feasibility {
    let total_checks = candidates as u128 * checks_per_candidate as u128;
    let seconds = if rate_per_sec == 0 {
        u64::max_value()
    } else {
        (total_checks / rate_per_sec as u128) as u64
    };
    Feasibility {
        total_checks,
        seconds,
    }
}

pub fn fmt_duration(total: u64) -> String {
    let days = total / 86400;
    let hours = (total % 86400) / 3600;
    let minutes = (total % 3600) / 60;
    format!("{}d {}h {}m", days, hours, minutes)
}
