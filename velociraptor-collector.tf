locals {
  environment = {
    VELOCIRAPTOR_TARGET_ARGS = jsonencode({
      bucket = var.gcp_source_bucket_name
      GCSKey = {
        type                        = var.gcp_source_bucket_service_account_key.type
        project_id                  = var.gcp_source_bucket_service_account_key.project_id
        private_key_id              = var.gcp_source_bucket_service_account_key.private_key_id
        private_key                 = var.gcp_source_bucket_service_account_key.private_key
        client_email                = var.gcp_source_bucket_service_account_key.client_email
        client_id                   = var.gcp_source_bucket_service_account_key.client_id
        auth_uri                    = var.sgcp_source_bucket_service_account_key.auth_uri
        token_uri                   = var.gcp_source_bucket_service_account_key.token_uri
        auth_provider_x509_cert_url = var.gcp_source_bucket_service_account_key.auth_provider_x509_cert_url
        client_x509_cert_url        = var.gcp_source_bucket_service_account_key.client_x509_cert_url
      }
    })
  }
}

resource "null_resource" "velociraptor_windows" {
  provisioner "local-exec" {
    quiet = true
    environment = local.environment
    interpreter = ["/bin/bash", "-c"]
    command = <<EOF
      # Collect the tools
      velociraptor config generate --merge '{"Datastore": {"location": "/tmp/velociraptor_windows", "filestore_directory": "/tmp/velociraptor_windows"}}' > server.config.yaml
      velociraptor --config server.config.yaml artifacts collect Server.Internal.ToolDependencies

       # Create the collector
       velociraptor --config server.config.yaml artifacts collect Server.Utils.CreateCollector \
      --args OS=Windows \
      --args artifacts='["Windows.KapeFiles.Targets"]' \
      --args parameters='{"Windows.KapeFiles.Targets":{"VSSAnalysisAge":"1000","_SANS_Triage":"Y”}}' \
      --args opt_filename_template="Collection-Windows-%FQDN%-%TIMESTAMP%" \
      --output windows.zip \
      --args target=GCS \
      --args target_args="$VELOCIRAPTOR_TARGET_ARGS" \
      --args opt_prompt=N \
      --args opt_admin=Y \
      --args opt_level=5 \
      --args opt_timeout=86400 \
      --args opt_format=jsonl
    EOF
  }
}
