use axum::{extract::State, response::IntoResponse};
use iroh_net::NodeId;
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;

use crate::http::extract::Json;
use crate::state::AppState;

use super::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRequest {
    node_id: NodeId,
    home_derp: Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResponse {
    published: bool,
    ttl: u16,
}

/// POST handler for resolvng DoH queries
pub async fn post(
    State(state): State<AppState>,
    Json(req): Json<PublishRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!(?req, "publish request");
    state.dns_server.publish_home_derp(req.node_id, req.home_derp).await?;
    Ok(Json(PublishResponse {
        published: true,
        ttl: 900,
    }))
}
