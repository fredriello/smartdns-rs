use std::path::PathBuf;
use std::time::Duration;

use super::*;
use options::parse_value;

impl NomParser for CfstMode {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map(preceded(tag_no_case("tcp:"), u16), CfstMode::Tcp),
            value(CfstMode::Httping, tag_no_case("httping")),
            value(CfstMode::Download, tag_no_case("download")),
        ))
        .parse(input)
    }
}

impl NomParser for Vec<CfstMode> {
    fn parse(input: &str) -> IResult<&str, Self> {
        separated_list1(char(','), CfstMode::parse).parse(input)
    }
}

/// Parse duration strings like "1h", "30m", "2h30m", or plain seconds.
pub fn parse_cfst_duration(input: &str) -> IResult<&str, Duration> {
    alt((parse_hm_duration, map(u64, Duration::from_secs))).parse(input)
}

fn parse_hm_duration(input: &str) -> IResult<&str, Duration> {
    let (input, hours) = opt(terminated(u64, char('h'))).parse(input)?;
    let (input, minutes) = opt(terminated(u64, char('m'))).parse(input)?;

    if hours.is_none() && minutes.is_none() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let secs = hours.unwrap_or(0) * 3600 + minutes.unwrap_or(0) * 60;
    Ok((input, Duration::from_secs(secs)))
}

/// Parse speed strings like "5M" (megabytes/sec) -> 5*1024*1024 bytes/sec.
pub fn parse_cfst_speed(input: &str) -> IResult<&str, u64> {
    let (input, num) = u64(input)?;
    let (input, _) = tag_no_case("M").parse(input)?;
    Ok((input, num * 1024 * 1024))
}

impl NomParser for CfstDomainEntry {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, domain) = delimited(char('/'), Domain::parse, char('/')).parse(input)?;

        let mut entry = CfstDomainEntry {
            domain,
            url: None,
            ip_file: None,
            result_count: None,
        };

        let one = alt((
            map(
                parse_value(alt((tag("url"), tag("u"))), String::parse),
                |v| {
                    entry.url = Some(v);
                },
            ),
            map(
                parse_value(alt((tag("ip-file"), tag("f"))), PathBuf::parse),
                |v| {
                    entry.ip_file = Some(v);
                },
            ),
            map(
                parse_value(alt((tag("result-count"), tag("rc"))), NomParser::parse),
                |v| {
                    entry.result_count = Some(v);
                },
            ),
        ));

        let (input, _) = opt(preceded(space1, separated_list1(space1, one))).parse(input)?;

        Ok((input, entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cfst_mode_single() {
        assert_eq!(CfstMode::parse("tcp:443"), Ok(("", CfstMode::Tcp(443))));
        assert_eq!(CfstMode::parse("httping"), Ok(("", CfstMode::Httping)));
        assert_eq!(CfstMode::parse("download"), Ok(("", CfstMode::Download)));
    }

    #[test]
    fn test_parse_cfst_mode_list() {
        assert_eq!(
            Vec::<CfstMode>::parse("tcp:443,httping,download"),
            Ok((
                "",
                vec![CfstMode::Tcp(443), CfstMode::Httping, CfstMode::Download]
            ))
        );
    }

    #[test]
    fn test_parse_cfst_duration() {
        assert_eq!(
            parse_cfst_duration("1h"),
            Ok(("", Duration::from_secs(3600)))
        );
        assert_eq!(
            parse_cfst_duration("30m"),
            Ok(("", Duration::from_secs(1800)))
        );
        assert_eq!(
            parse_cfst_duration("2h30m"),
            Ok(("", Duration::from_secs(9000)))
        );
        assert_eq!(
            parse_cfst_duration("3600"),
            Ok(("", Duration::from_secs(3600)))
        );
    }

    #[test]
    fn test_parse_cfst_speed() {
        assert_eq!(parse_cfst_speed("5M"), Ok(("", 5 * 1024 * 1024)));
        assert_eq!(parse_cfst_speed("10M"), Ok(("", 10 * 1024 * 1024)));
    }

    #[test]
    fn test_parse_cfst_domain_entry() {
        let (rest, entry) = CfstDomainEntry::parse(
            "/cdn.example.com/ -url https://x.com/100m.bin -ip-file /etc/cf.txt -result-count 2",
        )
        .unwrap();
        assert_eq!(rest, "");
        assert_eq!(
            entry.domain,
            Domain::Name("cdn.example.com".parse().unwrap())
        );
        assert_eq!(entry.url, Some("https://x.com/100m.bin".to_string()));
        assert_eq!(entry.ip_file, Some(PathBuf::from("/etc/cf.txt")));
        assert_eq!(entry.result_count, Some(2));
    }

    #[test]
    fn test_parse_cfst_domain_entry_minimal() {
        let (rest, entry) = CfstDomainEntry::parse("/example.com/").unwrap();
        assert_eq!(rest, "");
        assert_eq!(entry.domain, Domain::Name("example.com".parse().unwrap()));
        assert_eq!(entry.url, None);
        assert_eq!(entry.ip_file, None);
        assert_eq!(entry.result_count, None);
    }
}
