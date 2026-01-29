use std::os::fd::RawFd;
use std::sync::{LazyLock, RwLock};
use std::{collections::BTreeMap, net::Ipv4Addr};

#[repr(u32)]
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub enum PifType {
    #[default]
    None = 0,
    Host,
    Tap,
    Splice,
    NumTypes,
}

type FlowAtSidx = BTreeMap<Flowside, StateIdx>;

pub static FLOWATSIDX: RwLock<FlowAtSidx> = RwLock::new(BTreeMap::new());

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct Flowside {
    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,
    pub srcport: u16,
    pub destport: u16,
}

impl Default for Flowside {
    fn default() -> Self {
        Flowside {
            src: Ipv4Addr::UNSPECIFIED,
            dest: Ipv4Addr::UNSPECIFIED,
            srcport: 0,
            destport: 0,
        }
    }
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

#[derive(Default, Clone, Copy, PartialEq)]
pub struct Ping {
    pub socket_fd: RawFd,
}

impl Ping {}

#[derive(Default, Clone, Copy, PartialEq)]
pub enum FlowState {
    Free,
    #[default]
    New,
    Ini,
    Tgt,
    Typed,
    Active,
    States,
}

#[derive(Default, Clone, Copy, PartialEq)]
pub enum FlowType {
    #[default]
    None,
    Tcp,
    TcpSplice,
    Ping,
    Udp,
    NumTypes,
}

#[derive(Default, Clone, Copy, PartialEq)]
pub struct FlowCommon {
    pub flow_type: FlowType,
    pub flow_state: FlowState,
    pub pif: [PifType; 2],
}

#[derive(Default, PartialEq, Clone, Copy)]
pub struct Flow {
    pub flow_common: FlowCommon,
    pub side: [Flowside; 2],
    pub ping: Ping,
}

// we need a hash set of stateidx, should be flowmax instead

pub struct FlowAllocator {
    pub next_free: usize,
    pub flows: [Flow; 1024],
}

impl Default for FlowAllocator {
    fn default() -> Self {
        FlowAllocator {
            next_free: 0,
            flows: [Flow::default(); 1024],
        }
    }
}

pub static FLOWS: LazyLock<RwLock<FlowAllocator>> =
    LazyLock::new(|| RwLock::new(FlowAllocator::default()));

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
