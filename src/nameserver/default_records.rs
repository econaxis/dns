pub const DEFAULT_RECORDS: &[&str] = &[
    "henryn.xyz A 127.0.0.5",
    "a.henryn.xyz A 127.0.0.3",
    "b.henryn.xyz A 127.0.0.4",
    "www1.henryn.xyz NS ns1.henryn.xyz",
    "www2.henryn.xyz NS ns2.henryn.xyz",
    "a.www1.henryn.xyz A 127.0.0.6",
    "a.www2.henryn.xyz A 127.0.1.6",
    "b.www2.henryn.xyz CNAME c.www2.henryn.xyz",
    "c.www2.henryn.xyz CNAME httpbin.org",
    "ns1.henryn.xyz A 127.0.0.2",
    "ns2.henryn.xyz A 127.0.0.3",
    "largetext.www2.henryn.xyz CNAME b.henryn.xyz",
    r#"acme.www2.henryn.xyz TXT AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    fldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjas
    fldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjas
    fldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjasfldsakjf ds;alfkjas
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "#,

    "bc.www2.henryn.xyz CNAME cb.www2.henryn.xyz",
    "cb.www2.henryn.xyz CNAME c.www2.henryn.xyz",
];