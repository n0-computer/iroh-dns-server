use crate::http::error::AppError;

use async_trait::async_trait;
use axum::{extract::{rejection::JsonRejection, FromRequest, Request}, response::{IntoResponse, Response}};
use http::StatusCode;
use serde::Serialize;

// We define our own `Json` extractor that customizes the error from `axum::Json`
pub struct Json<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for Json<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = AppError;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, body);
        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => Err(AppError::new(StatusCode::BAD_REQUEST, Some(rejection))),
        }
    }
}
impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}
