# PathSphere 3D GKE/GCVE reference provisioning (stub)
# Prereqs: GKE Autopilot cluster, Vault + External Secrets operator, OIDC federation.

terraform {
  required_version = ">= 1.5"
  backend "gcs" {
    bucket = "pathsphere-tfstate"
  }
}

variable "project_id" { type = string }
variable "region" { default = "us-central1" }
variable "environment" { default = "dev" }
variable "tenant_ids" { type = list(string) }

# Config Connector managed resources
resource "google_service_identity" "ps3d" {
  provider   = google-beta
  project    = var.project_id
  service    = "compute.googleapis.com"
  role       = "roles/iam.serviceAccountTokenCreator"
  depends_on = [google_project_service.compute]
}

resource "google_project_service" "compute" {
  project = var.project_id
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "postgres" {
  project = var.project_id
  service = "sqladmin.googleapis.com"
  disable_on_destroy = false
}

resource "google_sql_database_instance" "ps3d" {
  provider            = google-beta
  name                = "ps3d-${var.environment}"
  database_version    = "POSTGRES_16"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = true
    }
    backup_configuration {
      enabled            = true
      start_time         = "03:00"
      point_in_time_recovery_enabled = true
    }
  }
}

resource "google_sql_database" "semantic" {
  name     = "semantic"
  instance = google_sql_database_instance.ps3d.name
}

resource "google_redis_instance" "cache" {
  name           = "ps3d-cache-${var.environment}"
  memory_size_gb = 4
  tier           = "STANDARD_HA"
}

# WORM bucket (Object Lock)
resource "google_storage_bucket" "reports" {
  name          = "ps3d-reports-${var.environment}"
  location      = var.region
  force_destroy = false
  storage_class = "STANDARD"
  lifecycle_rule {
    condition { age = 30 }
    action   { type = "SetStorageClass", storage_class = "COLDLINE" }
  }
  retention_policy {
    is_locked            = true
    retention_period     = 2592000 # 30 days min retention (WORM)
  }
}

output "endpoint" {
  value = google_sql_database_instance.ps3d.public_ip_address
}

# NOTE: Neo4j Aura/GCVE Cohere and OPA discovery are provisioned by
# the operator plane; secrets resolved from Vault via ExternalSecret.