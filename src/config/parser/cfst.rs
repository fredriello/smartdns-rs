//! Parser for cfst-* configuration directives.

use super::*;

use crate::config::{CfstDomainRule, CfstMode};

/// Parse cfst-mode value like "tcp:443", "tcp:443,httping", "tcp:443,httping,download"
pub fn parse_cfst_mode(input: &str) -> IResult<&str, CfstMode> {
    alt((
        value(
            CfstMode::TcpHttpingDownload,
            alt((
                tag_no_case("tcp:443,httping,download"),
                tag_no_case("download"),
            )),
        ),
        value(
            CfstMode::TcpHttping,
            alt((tag_no_case("tcp:443,httping"), tag_no_case("httping"))),
        ),
        value(
            CfstMode::Tcp,
            alt((tag_no_case("tcp:443"), tag_no_case("tcp"))),
        ),
    ))
    .parse(input)
}

impl NomParser for CfstMode {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse_cfst_mode(input)
    }
}

/// Parse a duration like "1h", "30m", "300", "300s"
pub fn parse_duration(input: &str) -> IResult<&str, std::time::Duration> {
    let (input, num) = u64(input)?;
    let (input, unit) = opt(alt((
        char('h'),
        char('m'),
        char('s'),
        char('H'),
        char('M'),
        char('S'),
    )))
    .parse(input)?;
    let secs = match unit {
        Some('h') | Some('H') => num * 3600,
        Some('m') | Some('M') => num * 60,
        _ => num, // seconds by default
    };
    Ok((input, std::time::Duration::from_secs(secs)))
}

/// Parse speed like "5M", "10m", "1024k", or raw bytes/sec
pub fn parse_speed(input: &str) -> IResult<&str, u64> {
    let (input, num) = u64(input)?;
    let (input, unit) = opt(alt((
        char('M'),
        char('m'),
        char('K'),
        char('k'),
        char('G'),
        char('g'),
    )))
    .parse(input)?;
    let bytes_per_sec = match unit {
        Some('G') | Some('g') => num * 1_000_000_000 / 8,
        Some('M') | Some('m') => num * 1_000_000 / 8,
        Some('K') | Some('k') => num * 1_000 / 8,
        _ => num,
    };
    Ok((input, bytes_per_sec))
}

/// Parse cfst-domain line: /domain/ [-url <url>] [-ip-file <path>] [-result-count <num>]
pub fn parse_cfst_domain(input: &str) -> IResult<&str, CfstDomainRule> {
    let (input, domain) = Domain::parse(input)?;
    let (input, _) = space0(input)?;

    let mut url = None;
    let mut ip_file = None;
    let mut result_count = None;

    let mut remaining = input;
    loop {
        let (input, _) = space0(remaining)?;
        if input.is_empty() {
            remaining = input;
            break;
        }

        if let Ok((input, _)) = tag_no_case::<&str, &str, nom::error::Error<&str>>("-url")(input) {
            let (input, _) = space1(input)?;
            let (input, val) = is_not(" \t\r\n")(input)?;
            url = Some(
                url::Url::parse(val)
                    .map_err(|_| nom::Err::Failure(nom::error::Error::new(val, nom::error::ErrorKind::Verify)))?,
            );
            remaining = input;
            continue;
        }

        if let Ok((input, _)) =
            tag_no_case::<&str, &str, nom::error::Error<&str>>("-ip-file")(input)
        {
            let (input, _) = space1(input)?;
            let (input, val) = PathBuf::parse(input)?;
            ip_file = Some(val);
            remaining = input;
            continue;
        }

        if let Ok((input, _)) =
            tag_no_case::<&str, &str, nom::error::Error<&str>>("-result-count")(input)
        {
            let (input, _) = space1(input)?;
            let (input, val) = usize::parse(input)?;
            result_count = Some(val);
            remaining = input;
            continue;
        }

        // Unknown option, stop parsing
        remaining = input;
        break;
    }

    Ok((
        remaining,
        CfstDomainRule {
            domain,
            ip_file,
            url,
            result_count,
        },
    ))
}

impl NomParser for CfstDomainRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse_cfst_domain(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cfst_mode() {
        assert_eq!(CfstMode::parse("tcp:443"), Ok(("", CfstMode::Tcp)));
        assert_eq!(
            CfstMode::parse("tcp:443,httping"),
            Ok(("", CfstMode::TcpHttping))
        );
        assert_eq!(
            CfstMode::parse("tcp:443,httping,download"),
            Ok(("", CfstMode::TcpHttpingDownload))
        );
        assert_eq!(CfstMode::parse("download"), Ok(("", CfstMode::TcpHttpingDownload)));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(
            parse_duration("1h"),
            Ok(("", std::time::Duration::from_secs(3600)))
        );
        assert_eq!(
            parse_duration("30m"),
            Ok(("", std::time::Duration::from_secs(1800)))
        );
        assert_eq!(
            parse_duration("300"),
            Ok(("", std::time::Duration::from_secs(300)))
        );
    }

    #[test]
    fn test_parse_speed() {
        assert_eq!(parse_speed("5M"), Ok(("", 5_000_000 / 8)));
        assert_eq!(parse_speed("1024k"), Ok(("", 1_024_000 / 8)));
        assert_eq!(parse_speed("1000"), Ok(("", 1000)));
    }

    #[test]
    fn test_parse_cfst_domain_simple() {
        let (_, rule) = CfstDomainRule::parse("/cdn.example.com/").unwrap();
        assert_eq!(rule.domain.to_string(), "cdn.example.com");
        assert!(rule.url.is_none());
        assert!(rule.ip_file.is_none());
        assert!(rule.result_count.is_none());
    }

    #[test]
    fn test_parse_cfst_domain_with_options() {
        let input = "/assets.example.com/ -url https://assets.example.com/100m.bin -result-count 2";
        let (_, rule) = CfstDomainRule::parse(input).unwrap();
        assert_eq!(rule.domain.to_string(), "assets.example.com");
        assert_eq!(
            rule.url.unwrap().as_str(),
            "https://assets.example.com/100m.bin"
        );
        assert_eq!(rule.result_count, Some(2));
    }
}
