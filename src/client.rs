use crate::config::Config;
use crate::config::VpnPeer;
use crate::{Behaviour, Event, Result, MTU};
use async_std::fs::File;
use async_std::io::BufWriter;
use async_tun::Tun;
use bimap::BiMap;
use cidr::Ipv4Cidr;
use etherparse::InternetSlice;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::core::network::Peer;
use libp2p::core::DialOpts;
use libp2p::request_response::RequestId;
use libp2p::swarm::behaviour;
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    mdns::MdnsEvent,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm
};

use std::{collections::BTreeMap, net::Ipv4Addr, str::FromStr};

#[derive(Debug)]
pub enum Error {
    PrivilegedUser
}

impl std::fmt::Display for Error {
    fn fmt(&self,f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!( f, "swarm should not to be run as root")
    }
}

impl std::error::Error for Error {}

pub struct Client {
    listen: Multiaddr,
    peer_routing_table: BiMap<Ipv4Addr, PeerId>,
    tun: Option<Tun>,
    swarm: Swarm<Behaviour>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        Default::default()
    }

    pub async fn run(&mut self) -> Result<()> {
        if users::get_current_uid() == 0
        || users::get_effective_gid() == 0
        || users::get_current_gid() == 0
        || users::get_effective_gid() == 0 
        {
            return Err(Box::new(Error::PrivilegedUser));
        }

        let listener_id = self.swarm.listen_on(self.listen.clone())?;

        let mut packet = [0u8; MTU];

        let tun = self.tun.take().expect("Tun should not to be None");
        let mut tun_reader = tun.reader();
        let mut tun_writer = tun.writer();
        log::debug!("Stratinig Swarm");
        log::debug!("Peer riuting table:");

        for (addr, peer_id) in &self.peer_routing_table {
            log::debug!("{addr}: {peer_id}")
        } loop {
            use futures::{prelude::*, select};
            let mut tun_reader_fut = tun_reader.read(&mut packet).fuse();
            select! {
                _ = tun_reader_fut => {
                    log::trace!("Recieved packet on tun: {:?}", packet);
                    self.handle_tun_packet(packet);
                }
                event = self.swarm.select_next_some() => match event {
                   SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                    peer,
                    message: RequestResponseMessage::Request { request, ..},
                   })) => {
                    packet.copy_from_slice(&request[0..MTU]);
                    log::trace!("Reiceved packet from peer: {} - {:?}", peer.to_base58(), packet);
                    self.handle_peer_packet(peer, packet, &mut tun_writer).await?;
                   }
                   SwarmEvent::Behaviour(Event::Mdns(MdnsEvent::Discovered(addresses))) => {
                    for (peer_id, _) in addresses {
                        log::debug!("New peer connection: {}", peer_id.to_base58())
                        }
                   }
                   SwarmEvent::Behaviour(_) => {}
                   SwarmEvent::NewListenAddr { address, .. } => {
                    log::info!("Now listening on: {address:?}");
                   }
                   SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    log::info!("Established connection to: {}", peer_id.to_base58());
                   }
                   SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    log::info!("Closed connection to {}", peer_id.to_base58());
                   }
                   e => log::info!("{e:?}")
                }
            }
        }
    }

    fn handle_tun_packet(&mut self, packet: [u8; MTU]) {
        let sliced_pack = match etherparse::SlicedPacket::from_ip(&packet) {
            Ok(p) => p,
            Err(e) => {
                log::info!("Could not parse packet recieved on TUN device");
                return;
            }
        };
        match sliced_pack.ip {
            Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
                let daddr = header_slice.destination_addr();
                log::debug!("Packet is destined on {}", daddr);
                
                if let Some(peer_id) = self.peer_routing_table.get_by_left(&daddr) {
                    log::debug!("Associated peer: {peer_id}");
                    self.swarm 
                        .behaviour_mut()
                        .request_responce
                        .send_request(peer_id, packet.to_vec());
                } else {
                    log::debug!("No peer corresponding to destination address")
                }
            }
            _ => {
                log::trace!("Unsupported packet type!");
            }
        }
    }

    async fn handle_peer_packet(
        &mut self, 
        peer: PeerId,
        packet: [u8; MTU],
        tun_writer: &mut BufWriter<&File>,
    ) -> std::io::Result<()> {
        if let Some(saddr) = self.peer_routing_table.get_by_right(&peer) {
            let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
                Ok(p) => p,
                Err(_) => {
                    log::info!("Could not parse packet recieved from peer");
                    return Ok(())
                }
            };
            match sliced_packet.ip {
                Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
                    let packet_saddr = header_slice.source_addr();
                    if packet_saddr != *saddr {
                        log::warn!("Packet with different source addr recieved from {peer}. Expected: {saddr}, got {packet_saddr}");
                    }
                    tun_writer.write_all(&packet).await?;
                }
                _ => {
                    log::trace!("Unsupported packet type")
                }
            }
        }
        Ok(())
    }
}

pub struct ClientBuilder {
    config: Option<Config>,
    tun: Option<Tun>
}
impl ClientBuilder {
    pub async fn build(self) -> Result<Client> {
        let cfg = self.config.ok_or("config not set")?;
        let mut peers = BTreeMap::new();
        let mut peer_routing_table = BiMap::new();
        for VpnPeer {
            ip4_addr,
            peer_id,
            swarm_addr,
        } in cfg.peers()
        {
            peers.insert(*peer_id, swarm_addr.clone());
            peer_routing_table.insert(*ip4_addr, *peer_id);
        }
        Ok(Client {
            listen: cfg.listen().clone(),
            peer_routing_table,
            tun: Some(self.tun.ok_or("tun not set")?),
            swarm: {
                let pub_key = cfg.keypair().public();
                let peer_id = PeerId::from(pub_key.clone());
                let transport = development_transport(cfg.keypair()).await?;
                let mut behaviour = Behaviour::new(peer_id, pub_key).await?;
                for (peer_id, swarm_addr) in peers {
                    if let Some(addr) = swarm_addr {
                        behaviour.kademlia.add_address(&peer_id, addr.clone());
                    }
                }
                for (peer_id, addr) in cfg.bootaddrs() {
                    behaviour.kademlia.add_address(&peer_id, addr.clone());
                }
                Swarm::new(transport, behaviour, peer_id)
            },
        })
    }

    pub fn config(self, config: Config) -> Self {
        Self {
            config: Some(config),
            tun: self.tun,
        }
    }

    pub fn tun(self, tun: Tun) -> Self {
        Self {
            config: self.config,
            tun: Some(tun),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            config: None,
            tun: None,
        }
    }
}