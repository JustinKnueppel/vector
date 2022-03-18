use bytes::Bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::{
    codecs::{
        self,
        decoding::{DeserializerConfig, FramingConfig},
    },
    config::log_schema,
    event::Event,
    serde::default_decoding,
    sources::util::{SocketListenAddr, TcpNullAcker, TcpSource},
    tcp::TcpKeepaliveConfig,
    tls::{TlsConfig, CertificateMetadata},
};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TcpConfig {
    address: SocketListenAddr,
    keepalive: Option<TcpKeepaliveConfig>,
    max_length: Option<usize>,
    #[serde(default = "default_shutdown_timeout_secs")]
    shutdown_timeout_secs: u64,
    host_key: Option<String>,
    tls: Option<TlsConfig>,
    receive_buffer_bytes: Option<usize>,
    framing: Option<FramingConfig>,
    #[serde(default = "default_decoding")]
    decoding: DeserializerConfig,
    pub connection_limit: Option<u32>,
}

const fn default_shutdown_timeout_secs() -> u64 {
    30
}

impl TcpConfig {
    pub const fn new(
        address: SocketListenAddr,
        keepalive: Option<TcpKeepaliveConfig>,
        max_length: Option<usize>,
        shutdown_timeout_secs: u64,
        host_key: Option<String>,
        tls: Option<TlsConfig>,
        receive_buffer_bytes: Option<usize>,
        framing: Option<FramingConfig>,
        decoding: DeserializerConfig,
        connection_limit: Option<u32>,
    ) -> Self {
        Self {
            address,
            keepalive,
            max_length,
            shutdown_timeout_secs,
            host_key,
            tls,
            receive_buffer_bytes,
            framing,
            decoding,
            connection_limit,
        }
    }

    pub fn from_address(address: SocketListenAddr) -> Self {
        Self {
            address,
            keepalive: None,
            max_length: Some(crate::serde::default_max_length()),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            host_key: None,
            tls: None,
            receive_buffer_bytes: None,
            framing: None,
            decoding: default_decoding(),
            connection_limit: None,
        }
    }

    pub const fn host_key(&self) -> &Option<String> {
        &self.host_key
    }

    pub const fn tls(&self) -> &Option<TlsConfig> {
        &self.tls
    }

    pub const fn framing(&self) -> &Option<FramingConfig> {
        &self.framing
    }

    pub const fn decoding(&self) -> &DeserializerConfig {
        &self.decoding
    }

    pub const fn address(&self) -> SocketListenAddr {
        self.address
    }

    pub const fn keepalive(&self) -> Option<TcpKeepaliveConfig> {
        self.keepalive
    }

    pub const fn max_length(&self) -> Option<usize> {
        self.max_length
    }

    pub const fn shutdown_timeout_secs(&self) -> u64 {
        self.shutdown_timeout_secs
    }

    pub const fn receive_buffer_bytes(&self) -> Option<usize> {
        self.receive_buffer_bytes
    }

    pub fn set_max_length(&mut self, val: Option<usize>) -> &mut Self {
        self.max_length = val;
        self
    }

    pub fn set_shutdown_timeout_secs(&mut self, val: u64) -> &mut Self {
        self.shutdown_timeout_secs = val;
        self
    }

    pub fn set_tls(&mut self, val: Option<TlsConfig>) -> &mut Self {
        self.tls = val;
        self
    }

    pub fn set_framing(&mut self, val: Option<FramingConfig>) -> &mut Self {
        self.framing = val;
        self
    }

    pub fn set_decoding(&mut self, val: DeserializerConfig) -> &mut Self {
        self.decoding = val;
        self
    }
}

#[derive(Debug, Clone)]
pub struct RawTcpSource {
    config: TcpConfig,
    decoder: codecs::Decoder,
}

impl RawTcpSource {
    pub const fn new(config: TcpConfig, decoder: codecs::Decoder) -> Self {
        Self { config, decoder }
    }
}

impl TcpSource for RawTcpSource {
    type Error = codecs::decoding::Error;
    type Item = SmallVec<[Event; 1]>;
    type Decoder = codecs::Decoder;
    type Acker = TcpNullAcker;

    fn decoder(&self) -> Self::Decoder {
        self.decoder.clone()
    }

    fn handle_events(&self, events: &mut [Event], host: Bytes, certificate_metadata: &Option<CertificateMetadata>) {
        handle_events(events, host, certificate_metadata, self.config.host_key.as_deref());
    }

    fn build_acker(&self, _: &[Self::Item]) -> Self::Acker {
        TcpNullAcker
    }
}

fn handle_events(events: &mut [Event], host: Bytes, certificate_metadata: &Option<CertificateMetadata>, self_host_key: Option<&str>) {
    let now = Utc::now();
    let host_key = self_host_key
        .unwrap_or_else(|| log_schema().host_key());

    for event in events {
        let log = event.as_mut_log();

        log.try_insert(log_schema().source_type_key(), Bytes::from("socket"));
        log.try_insert(log_schema().timestamp_key(), now);

        if let Some(certificate_metadata) = certificate_metadata {
            log.insert("certificate_metadata", certificate_metadata.to_string());
        }

        log.try_insert(host_key, host.clone());
    }
}

mod test {
    use chrono::DateTime;
    use bytes::Bytes;

    use crate::{
        config::log_schema,
        event::{Event, Value},
    };

    use vector_common::{btreemap, assert_event_data_eq};
    use super::*;

    
    #[test]
    fn handle_events_no_tls() {
        let mut events = vec!(Event::from(btreemap!(
            log_schema().timestamp_key() => Value::Timestamp(DateTime::parse_from_rfc3339("2015-09-07T01:23:04Z").unwrap().into()),
        )));

        let expected = Event::from(btreemap!(
            log_schema().timestamp_key() => Value::Timestamp(DateTime::parse_from_rfc3339("2015-09-07T01:23:04Z").unwrap().into()),
            "host" => "host",
            log_schema().source_type_key() => "socket"
        ));

        handle_events(&mut events, Bytes::from("host"), &None, Some("host"));

        assert_event_data_eq!(expected, events[0])
    }
    
    #[test]
    fn handle_events_with_tls() {
        let mut events = vec!(Event::from(btreemap!(
            log_schema().timestamp_key() => Value::Timestamp(DateTime::parse_from_rfc3339("2015-09-07T01:23:04Z").unwrap().into()),
        )));

        let peer_cert = CertificateMetadata {
            country_name: Some("USA".to_owned()),
            state_or_province_name: Some("California".to_owned()),
            locality_name: None,
            organization_name: Some("Vector".to_owned()),
            organizational_unit_name: None,
            common_name: Some("Common name".to_owned()),
        };

        let expected = Event::from(btreemap!(
            log_schema().timestamp_key() => Value::Timestamp(DateTime::parse_from_rfc3339("2015-09-07T01:23:04Z").unwrap().into()),
            "host" => "host",
            log_schema().source_type_key() => "socket",
            "certificate_metadata" => &peer_cert.to_string()[..],
        ));

        handle_events(&mut events, Bytes::from("host"), &Some(peer_cert), Some("host"));

        assert_event_data_eq!(expected, events[0])
    }
}
