use std::{collections::BTreeMap, net::Ipv4Addr};

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PifType {
    None = 0,
    Host,
    Tap,
    Splice,
    NumTypes,
}

type FlowAtSidx = BTreeMap<Flowside, StateIdx>;

pub static mut FLOWATSIDX: FlowAtSidx = BTreeMap::new();

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct Flowside {
    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,
    pub srcport: u16,
    pub destport: u16,
}

impl Flowside {
    pub fn new(src: Ipv4Addr, dest: Ipv4Addr, srcport: u16, destport: u16) -> Self {
        Flowside {
            src,
            dest,
            srcport,
            destport,
        }
    }
}

pub struct StateIdx {
    // whats in a sidx
    pub sidei: u8, // which side from the two flowside entries in the flow array is this referring to
    pub flow_table_idx: usize,
}

#[derive(Default, Clone, Copy)]
struct Ping {}

impl Ping {}

#[derive(Clone, Copy)]
enum FlowState {
    Free,
    New,
    Ini,
    Tgt,
    Typed,
    Active,
    States,
}

#[derive(Clone, Copy)]
pub enum FlowType {
    None,
    Tcp,
    TcpSplice,
    Ping,
    Udp,
    NumTypes,
}

#[derive(Clone, Copy)]
pub struct FlowCommon {
    pub flow_type: FlowType,
    pub flow_state: FlowState,
    pub pif: [PifType; 2],
}

#[derive(Clone, Copy)]
pub struct Flow {
    pub flow_common: FlowCommon,
    pub side: [Flowside; 2],
    pub ping: Ping,
}

impl Flow {
    pub fn new() -> Self {
        Flow {
            flow_common: FlowCommon {
                flow_type: FlowType::None,
                flow_state: FlowState::New,
                pif: [PifType::None, PifType::None],
            },
            side: [
                Flowside {
                    src: Ipv4Addr::new(0, 0, 0, 0),
                    dest: Ipv4Addr::new(0, 0, 0, 0),
                    srcport: 0,
                    destport: 0,
                },
                Flowside {
                    src: Ipv4Addr::new(0, 0, 0, 0),
                    dest: Ipv4Addr::new(0, 0, 0, 0),
                    srcport: 0,
                    destport: 0,
                },
            ],
            ping: Ping {},
        }
    }
}

// we need a hash set of stateidx, should be flowmax instead
type FlowTable = [Flow; 1024];

struct FlowAllocator {
    pub next_free: usize,
    pub flows: FlowTable,
}

pub static mut FLOWS: FlowAllocator = FlowAllocator {
    next_free: 0,
    flows: [Flow {
        side: [
            Flowside {
                src: Ipv4Addr::new(0, 0, 0, 0),
                dest: Ipv4Addr::new(0, 0, 0, 0),
                srcport: 0,
                destport: 0,
            },
            Flowside {
                src: Ipv4Addr::new(0, 0, 0, 0),
                dest: Ipv4Addr::new(0, 0, 0, 0),
                srcport: 0,
                destport: 0,
            },
        ],
        ping: Ping {},
    }; 1024],
};

pub fn flow_initiate_af(
    flow: &mut Flow,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    sport: u16,
    dport: u16,
    pif: PifType,
) -> Flowside {
    let mut flowside = flow.side[0]; // 0 is iniside
    flowside.dest = daddr;
    flowside.src = saddr;
    flowside.destport = dport;
    flowside.srcport = sport;
    flow.flow_common.pif[0] = pif;
    flowside
}
