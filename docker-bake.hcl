group "default" {
  targets = ["tarnished-api"]
}

target "tarnished-api" {
  context = "."
  dockerfile = "Dockerfile"
  # Use templating to dynamically tag images for each platform
  tags = [
    "ghcr.io/markcoleman/tarnished-api:latest",
  ]
  # Pass any build arguments if needed
  args = {
    # Example: BUILD_DATE = "{{.Date}}"
    # You can also define a version argument to use in your Dockerfile:
    # VERSION = "1.0.0"
  }
}