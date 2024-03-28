use std::time::Duration;

use governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::PeerIpKeyExtractor, GovernorLayer,
};

/// Create the default rate-limiting layer.
///
/// This spawns a background thread to clean up the rate limiting cache.
pub fn create() -> GovernorLayer<'static, PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>> {
    // configure rate limiting
    // Allow bursts with up to five requests per IP address
    // and replenishes one element every two seconds
    // We Box it because Axum 0.6 requires all Layers to be Clone
    // and thus we need a static reference to it
    let governor_conf = Box::new(
        GovernorConfigBuilder::default()
            .per_second(4)
            .burst_size(2)
            .finish()
            .unwrap(),
    );

    let governor_limiter = governor_conf.limiter().clone();
    let interval = Duration::from_secs(60);
    // a separate background task to clean up
    std::thread::spawn(move || loop {
        std::thread::sleep(interval);
        tracing::debug!("rate limiting storage size: {}", governor_limiter.len());
        governor_limiter.retain_recent();
    });
    let layer = GovernorLayer {
        // We can leak this because it is created once and then
        config: Box::leak(governor_conf),
    };
    layer
}
