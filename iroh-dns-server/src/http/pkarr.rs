use anyhow::Result;
use axum::extract::Path;
use axum::{extract::State, response::IntoResponse};
use bytes::Bytes;
use hickory_proto::serialize::binary::BinDecodable;
use http::StatusCode;
use iroh_dns::packet::NodeAnnounce;
use iroh_net::NodeId;
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;

use crate::http::extract::Json;
use crate::state::AppState;

use super::error::AppError;

pub async fn put(
    State(state): State<AppState>,
    Path(key): Path<String>,
    body: Bytes, // Json(req): Json<PublishRequest>,
) -> Result<impl IntoResponse, AppError> {
    let key = pkarr::PublicKey::try_from(key.as_str())
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(format!("invalid key: {e}"))))?;
    let signed_packet = pkarr::SignedPacket::from_relay_response(key, body).map_err(|e| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            Some(format!("invalid body payload: {e}")),
        )
    })?;

    let an = NodeAnnounce::from_pkarr_signed_packet(signed_packet)?;
    info!(?an, "put node announce via pkarr");
    let _updated = state.dns_server.authority.insert_node_announce(an).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get(State(_state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    Ok(AppError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        Some("unimplemented"),
    ))
}

// fn simple_dns_to_hickory(
//     signed_packet: &pkarr::SignedPacket,
// ) -> Result<hickory_proto::op::Message> {
//     let encoded = signed_packet.encoded_packet();
//     println!("encoded {} {}", encoded.len(), hex::encode(&encoded));
//     let parsed1 = pkarr::dns::Packet::parse(&encoded)?;
//     println!("simpdns {parsed1:#?}");
//     let parsed2 = hickory_proto::op::Message::from_bytes(&encoded)?;
//     println!("hickory {parsed2:#?}");
//     Ok(parsed2)
// }
//
