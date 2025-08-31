//! Route pattern extraction utilities.

use actix_web::HttpRequest;

/// Extract route pattern from request, handling common patterns
///
/// Returns the actual path for API routes since they're well-defined.
/// This could be enhanced to group similar routes if needed.
pub fn extract_route_pattern(req: &HttpRequest) -> String {
    let path = req.path();

    // Return the actual path for our API routes since they're well-defined
    // This could be enhanced to group similar routes if needed
    if path.starts_with('/') {
        path.to_string()
    } else {
        "/unknown".to_string()
    }
}
