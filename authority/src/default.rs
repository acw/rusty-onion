use std::net::{Ipv4Addr,Ipv6Addr};

pub struct DefaultAuthority {
    pub nickname: String,
    pub is_bridge: bool,
    pub address: Ipv4Addr,
    pub ip6_address: Option<(Ipv6Addr,u16)>,
    pub onion_port: u16,
    pub dir_port: u16,
    pub v3_ident: Vec<u8>,
    pub fingerprint: Vec<u8>,
}

lazy_static! {
// static const char *default_authorities[] = {
    pub static ref DEFAULT_AUTHORITIES: Vec<DefaultAuthority> = {
        let mut result = Vec::new();
//   "moria1 orport=9101 "
//     "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 "
//     "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
        result.push(DefaultAuthority {
            nickname: "moria1".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(128,31,0,39),
            ip6_address: None,
            onion_port: 9101,
            dir_port: 9131,
            v3_ident:    vec![0xD5, 0x86, 0xD1, 0x83, 0x09, 0xDE, 0xD4, 0xCD,
                              0x6D, 0x57, 0xC1, 0x8F, 0xDB, 0x97, 0xEF, 0xA9,
                              0x6D, 0x33, 0x05, 0x66],
            fingerprint: vec![0x96, 0x95, 0xDF, 0xC3, 0x5F, 0xFE, 0xB8, 0x61,
                              0x32, 0x9B, 0x9F, 0x1A, 0xB0, 0x4C, 0x46, 0x39,
                              0x70, 0x20, 0xCE, 0x31],
            });
//   "tor26 orport=443 "
//     "v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
//     "ipv6=[2001:858:2:2:aabb:0:563b:1526]:443 "
//     "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
        result.push(DefaultAuthority {
            nickname: "tor26".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(86,59,21,38),
            ip6_address: Some((Ipv6Addr::new(0x2001,0x0858,0x0002,0x0002,
                                             0xaabb,0x0000,0x563b,0x1526),443)),
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![0x14, 0xC1, 0x31, 0xDF, 0xC5, 0xC6, 0xF9, 0x36,
                              0x46, 0xBE, 0x72, 0xFA, 0x14, 0x01, 0xC0, 0x2A,
                              0x8D, 0xF2, 0xE8, 0xB4],
            fingerprint: vec![0x84, 0x7b, 0x1F, 0x85, 0x03, 0x44, 0xD7, 0x87,
                              0x64, 0x91, 0xA5, 0x48, 0x92, 0xF9, 0x04, 0x93,
                              0x4E, 0x4E, 0xB8, 0x5D]
            });
//   "dizum orport=443 "
//     "v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 "
//     "194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
        result.push(DefaultAuthority {
            nickname: "dizum".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(194,109,206,212),
            ip6_address: None,
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![0xE8, 0xA9, 0xC4, 0x5E, 0xDE, 0x6D, 0x71, 0x12,
                              0x94, 0xFA, 0xDF, 0x8E, 0x79, 0x51, 0xF4, 0xDE,
                              0x6C, 0xA5, 0x6B, 0x58],
            fingerprint: vec![0x7E, 0xA6, 0xEA, 0xD6, 0xFD, 0x83, 0x08, 0x3C,
                              0x53, 0x8F, 0x44, 0x03, 0x8B, 0xBF, 0xA0, 0x77,
                              0x58, 0x7D, 0xD7, 0x55],
            });
//   "Bifroest orport=443 bridge "
//     "37.218.247.217:80 1D8F 3A91 C37C 5D1C 4C19 B1AD 1D0C FBE8 BF72 D8E1",
        result.push(DefaultAuthority {
            nickname: "Bifroest".to_string(),
            is_bridge: true,
            address: Ipv4Addr::new(37,218,247,217),
            ip6_address: None,
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![],
            fingerprint: vec![0x1D, 0x8F, 0x3A, 0x91, 0xC3, 0x7C, 0x5D, 0x1C,
                              0x4C, 0x19, 0xB1, 0xAD, 0x1D, 0x0C, 0xFB, 0xE8,
                              0xBF, 0x72, 0xD8, 0xE1],
            });
//   "gabelmoo orport=443 "
//     "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 "
//     "ipv6=[2001:638:a000:4140::ffff:189]:443 "
//     "131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
        result.push(DefaultAuthority {
            nickname: "gabelmoo".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(131,188,40,189),
            ip6_address: Some((Ipv6Addr::new(0x2001,0x0638,0xa000,0x4140,
                                             0x0000,0x0000,0xffff,0x0189),443)),
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![0xED, 0x03, 0xBB, 0x61, 0x6E, 0xB2, 0xF6, 0x0B,
                              0xEC, 0x80, 0x15, 0x11, 0x14, 0xBB, 0x25, 0xCE,
                              0xF5, 0x15, 0xB2, 0x26, ],
            fingerprint: vec![0xF2, 0x04, 0x44, 0x13, 0xDA, 0xC2, 0xE0, 0x2E,
                              0x3D, 0x6B, 0xCF, 0x47, 0x35, 0xA1, 0x9B, 0xCA,
                              0x1D, 0xE9, 0x72, 0x81, ],
            });
//   "dannenberg orport=443 "
//     "v3ident=0232AF901C31A04EE9848595AF9BB7620D4C5B2E "
//     "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
        result.push(DefaultAuthority {
            nickname: "dannenberg".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(193,23,244,244),
            ip6_address: None,
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![0x02, 0x32, 0xAF, 0x90, 0x1C, 0x31, 0xA0, 0x4E,
                              0xE9, 0x84, 0x85, 0x95, 0xAF, 0x9B, 0xB7, 0x62,
                              0x0D, 0x4C, 0x5B, 0x2E],
            fingerprint: vec![0x7B, 0xE6, 0x83, 0xE6, 0x5D, 0x48, 0x14, 0x13,
                              0x21, 0xC5, 0xED, 0x92, 0xF0, 0x75, 0xC5, 0x53,
                              0x64, 0xAC, 0x71, 0x23],
            });
//   "maatuska orport=80 "
//     "v3ident=49015F787433103580E3B66A1707A00E60F2D15B "
//     "ipv6=[2001:67c:289c::9]:80 "
//     "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
        result.push(DefaultAuthority {
            nickname: "maatuska".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(171,25,193,9),
            ip6_address: Some((Ipv6Addr::new(0x2001,0x067c,0x289c,0x0000,
                                             0x0000,0x0000,0x0000,0x0009),80)),
            onion_port: 80,
            dir_port: 443,
            v3_ident:    vec![0x49, 0x01, 0x5F, 0x78, 0x74, 0x33, 0x10, 0x35,
                              0x80, 0xE3, 0xB6, 0x6A, 0x17, 0x07, 0xA0, 0x0E,
                              0x60, 0xF2, 0xD1, 0x5B],
            fingerprint: vec![0xBD, 0x6A, 0x82, 0x92, 0x55, 0xCB, 0x08, 0xE6,
                              0x6F, 0xBE, 0x7D, 0x37, 0x48, 0x36, 0x35, 0x86,
                              0xE4, 0x6B, 0x38, 0x10],
            });
//   "Faravahar orport=443 "
//     "v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 "
//     "154.35.175.225:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC",
        result.push(DefaultAuthority {
            nickname: "Faravahar".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(154,35,175,225),
            ip6_address: None,
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![0xEF, 0xCB, 0xE7, 0x20, 0xAB, 0x3A, 0x82, 0xB9,
                              0x9F, 0x9E, 0x95, 0x3C, 0xD5, 0xBF, 0x50, 0xF7,
                              0xEE, 0xFC, 0x7B, 0x97],
            fingerprint: vec![0xCF, 0x6D, 0x0A, 0xAF, 0xB3, 0x85, 0xBE, 0x71,
                              0xB8, 0xE1, 0x11, 0xFC, 0x5C, 0xFF, 0x4B, 0x47,
                              0x92, 0x37, 0x33, 0xBC],
            });
//   "longclaw orport=443 "
//     "v3ident=23D15D965BC35114467363C165C4F724B64B4F66 "
//     "ipv6=[2620:13:4000:8000:60:f3ff:fea1:7cff]:443 "
//     "199.254.238.52:80 74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145",
        result.push(DefaultAuthority {
            nickname: "longclaw".to_string(),
            is_bridge: false,
            address: Ipv4Addr::new(199,254,238,52),
            ip6_address: Some((Ipv6Addr::new(0x2620,0x0013,0x4000,0x8000,
                                             0x0060,0xf3ff,0xfea1,0x7cff),443)),
            onion_port: 443,
            dir_port: 80,
            v3_ident:    vec![0x23, 0xD1, 0x5D, 0x96, 0x5B, 0xC3, 0x51, 0x14,
                              0x46, 0x73, 0x63, 0xC1, 0x65, 0xC4, 0xF7, 0x24,
                              0xB6, 0x4B, 0x4F, 0x66],
            fingerprint: vec![0x74, 0xA9, 0x10, 0x64, 0x6B, 0xCE, 0xEF, 0xBC,
                              0xD2, 0xE8, 0x74, 0xFC, 0x1D, 0xC9, 0x97, 0x43,
                              0x0F, 0x96, 0x81, 0x45],
            });
//   NULL
// };
        result
    };
}
