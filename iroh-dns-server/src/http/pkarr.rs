use anyhow::Result;
use axum::extract::Path;
use axum::{extract::State, response::IntoResponse};
use bytes::Bytes;

use http::StatusCode;



use tracing::info;



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

    let (node_id, updated) = state.dns_server.authority.upsert_pkarr(signed_packet)?;
    info!(?node_id, ?updated, "pkarr upsert");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get(State(_state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    // todo: implement pkarr relay get
    // let body = state.authority.announces.get(node_id).signed_packet.to_bytes()
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
