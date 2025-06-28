#################################################################################
# Secret ARNs and Names
#################################################################################

output "database_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = aws_secretsmanager_secret.database.arn
}

output "database_secret_name" {
  description = "Name of the database credentials secret"
  value       = aws_secretsmanager_secret.database.name
}

output "api_keys_secret_arn" {
  description = "ARN of the API keys secret"
  value       = aws_secretsmanager_secret.api_keys.arn
}

output "api_keys_secret_name" {
  description = "Name of the API keys secret"
  value       = aws_secretsmanager_secret.api_keys.name
}

output "storage_secret_arn" {
  description = "ARN of the storage credentials secret"
  value       = aws_secretsmanager_secret.storage.arn
}

output "storage_secret_name" {
  description = "Name of the storage credentials secret"
  value       = aws_secretsmanager_secret.storage.name
}

output "auth_secret_arn" {
  description = "ARN of the authentication secrets"
  value       = aws_secretsmanager_secret.auth.arn
}

output "auth_secret_name" {
  description = "Name of the authentication secrets"
  value       = aws_secretsmanager_secret.auth.name
}

output "clickhouse_secret_arn" {
  description = "ARN of the ClickHouse credentials secret"
  value       = aws_secretsmanager_secret.clickhouse.arn
}

output "clickhouse_secret_name" {
  description = "Name of the ClickHouse credentials secret"
  value       = aws_secretsmanager_secret.clickhouse.name
}

#################################################################################
# IAM Resources
#################################################################################

output "external_secrets_role_arn" {
  description = "ARN of the IAM role for External Secrets Operator"
  value       = aws_iam_role.external_secrets.arn
}

output "external_secrets_role_name" {
  description = "Name of the IAM role for External Secrets Operator"
  value       = aws_iam_role.external_secrets.name
}

output "external_secrets_policy_arn" {
  description = "ARN of the IAM policy for External Secrets Operator"
  value       = aws_iam_policy.external_secrets.arn
}

#################################################################################
# KMS Resources
#################################################################################

output "kms_key_arn" {
  description = "ARN of the KMS key for Secrets Manager encryption"
  value       = var.create_kms_key ? aws_kms_key.secrets_manager[0].arn : null
}

output "kms_key_id" {
  description = "ID of the KMS key for Secrets Manager encryption"
  value       = var.create_kms_key ? aws_kms_key.secrets_manager[0].key_id : null
}

output "kms_alias_name" {
  description = "Name of the KMS key alias"
  value       = var.create_kms_key ? aws_kms_alias.secrets_manager[0].name : null
}

#################################################################################
# Helper Information
#################################################################################

output "secret_prefix" {
  description = "Prefix used for all secrets"
  value       = var.secret_prefix
}

output "region" {
  description = "AWS region where resources are created"
  value       = var.region
}

output "external_secrets_namespace" {
  description = "Kubernetes namespace for External Secrets Operator"
  value       = var.external_secrets_namespace
}

output "external_secrets_service_account" {
  description = "Service account name for External Secrets Operator"
  value       = var.external_secrets_service_account
}

#################################################################################
# AWS CLI Commands for Secret Management
#################################################################################

output "secret_update_commands" {
  description = "AWS CLI commands to update secrets manually"
  value = {
    database = "aws secretsmanager update-secret --secret-id ${aws_secretsmanager_secret.database.name} --secret-string '{\"username\":\"your-username\",\"password\":\"your-password\"}'"
    api_keys = "aws secretsmanager update-secret --secret-id ${aws_secretsmanager_secret.api_keys.name} --secret-string '{\"openai_api_key\":\"sk-...\",\"anthropic_api_key\":\"sk-...\",\"gemini_api_key\":\"your-key\",\"helicone_api_key\":\"your-key\"}'"
    storage  = "aws secretsmanager update-secret --secret-id ${aws_secretsmanager_secret.storage.name} --secret-string '{\"s3_access_key\":\"your-access-key\",\"s3_secret_key\":\"your-secret-key\",\"minio_root_user\":\"your-user\",\"minio_root_password\":\"your-password\"}'"
    auth     = "aws secretsmanager update-secret --secret-id ${aws_secretsmanager_secret.auth.name} --secret-string '{\"better_auth_secret\":\"your-secret\",\"stripe_secret_key\":\"sk_...\"}'"
    clickhouse = "aws secretsmanager update-secret --secret-id ${aws_secretsmanager_secret.clickhouse.name} --secret-string '{\"user\":\"default\",\"password\":\"your-password\"}'"
  }
  sensitive = true
} 