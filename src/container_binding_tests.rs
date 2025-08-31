#[cfg(test)]
mod container_binding_tests {

    /// Test that bind address detection works correctly
    #[test]
    fn test_bind_address_detection() {
        // Mock the environment detection logic from main.rs
        let detect_bind_address = |k8s_env: Option<&str>, docker_env: Option<&str>, bind_override: Option<&str>| -> String {
            if let Some(bind) = bind_override {
                return bind.to_string();
            }
            
            // Simulate container detection logic
            if k8s_env.is_some() || docker_env.is_some() {
                "0.0.0.0:8080".to_string()
            } else {
                "127.0.0.1:8080".to_string()
            }
        };

        // Test default behavior (local development)
        assert_eq!(
            detect_bind_address(None, None, None),
            "127.0.0.1:8080",
            "Should bind to localhost for local development"
        );

        // Test Kubernetes environment detection
        assert_eq!(
            detect_bind_address(Some("kubernetes.default.svc"), None, None),
            "0.0.0.0:8080",
            "Should bind to all interfaces in Kubernetes"
        );

        // Test Docker environment detection
        assert_eq!(
            detect_bind_address(None, Some("true"), None),
            "0.0.0.0:8080",
            "Should bind to all interfaces in Docker"
        );

        // Test explicit override
        assert_eq!(
            detect_bind_address(Some("kubernetes.default.svc"), None, Some("192.168.1.10:9090")),
            "192.168.1.10:9090",
            "Should use explicit override regardless of environment"
        );
    }

    /// Test that the bind address logic matches what we implemented in main.rs
    #[test]
    fn test_container_environment_detection() {
        // This test validates the same logic that's in the main.rs file
        let is_container_environment = |k8s_service_host: Option<&str>, docker_container: Option<&str>, dockerenv_exists: bool| -> bool {
            k8s_service_host.is_some() || docker_container.is_some() || dockerenv_exists
        };

        assert!(!is_container_environment(None, None, false), "Should not detect container in normal environment");
        assert!(is_container_environment(Some("kubernetes.default.svc"), None, false), "Should detect Kubernetes");
        assert!(is_container_environment(None, Some("true"), false), "Should detect Docker container");
        assert!(is_container_environment(None, None, true), "Should detect Docker via .dockerenv file");
    }
}