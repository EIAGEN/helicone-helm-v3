provider "aws" {
  region = var.region
}

# Data source to get EKS cluster information
data "aws_eks_cluster" "cluster" {
  name = var.cluster_name
}

# Data source to get OIDC provider details
data "aws_iam_openid_connect_provider" "eks" {
  arn = var.oidc_provider_arn
}

locals {
  common_tags = merge(var.tags, {
    Component = "external-secrets"
  })
}

#################################################################################
# AWS Secrets Manager Secrets
#################################################################################

# Database credentials secret
resource "aws_secretsmanager_secret" "database" {
  name        = "${var.secret_prefix}/database"
  description = "Helicone database credentials"
  
  tags = merge(local.common_tags, {
    Category = "database"
  })
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = var.database_username
    password = var.database_password
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# API Keys secret
resource "aws_secretsmanager_secret" "api_keys" {
  name        = "${var.secret_prefix}/api-keys"
  description = "External API keys for LLM providers"
  
  tags = merge(local.common_tags, {
    Category = "api-keys"
  })
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    openai_api_key     = var.openai_api_key
    anthropic_api_key  = var.anthropic_api_key
    gemini_api_key     = var.gemini_api_key
    helicone_api_key   = var.helicone_api_key
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Storage credentials secret
resource "aws_secretsmanager_secret" "storage" {
  name        = "${var.secret_prefix}/storage"
  description = "S3/MinIO storage credentials"
  
  tags = merge(local.common_tags, {
    Category = "storage"
  })
}

resource "aws_secretsmanager_secret_version" "storage" {
  secret_id = aws_secretsmanager_secret.storage.id
  secret_string = jsonencode({
    s3_access_key       = var.s3_access_key
    s3_secret_key       = var.s3_secret_key
    minio_root_user     = var.minio_root_user
    minio_root_password = var.minio_root_password
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Authentication secrets
resource "aws_secretsmanager_secret" "auth" {
  name        = "${var.secret_prefix}/auth"
  description = "Authentication and authorization secrets"
  
  tags = merge(local.common_tags, {
    Category = "auth"
  })
}

resource "aws_secretsmanager_secret_version" "auth" {
  secret_id = aws_secretsmanager_secret.auth.id
  secret_string = jsonencode({
    better_auth_secret = var.better_auth_secret
    stripe_secret_key  = var.stripe_secret_key
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ClickHouse secrets
resource "aws_secretsmanager_secret" "clickhouse" {
  name        = "${var.secret_prefix}/clickhouse"
  description = "ClickHouse database credentials"
  
  tags = merge(local.common_tags, {
    Category = "clickhouse"
  })
}

resource "aws_secretsmanager_secret_version" "clickhouse" {
  secret_id = aws_secretsmanager_secret.clickhouse.id
  secret_string = jsonencode({
    user     = var.clickhouse_user
    password = var.clickhouse_password
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

#################################################################################
# IAM Role for External Secrets Operator
#################################################################################

# IAM Policy for External Secrets Operator
resource "aws_iam_policy" "external_secrets" {
  name        = "${var.cluster_name}-external-secrets-policy"
  description = "IAM policy for External Secrets Operator to access AWS Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.database.arn,
          aws_secretsmanager_secret.api_keys.arn,
          aws_secretsmanager_secret.storage.arn,
          aws_secretsmanager_secret.auth.arn,
          aws_secretsmanager_secret.clickhouse.arn,
          "${aws_secretsmanager_secret.database.arn}:*",
          "${aws_secretsmanager_secret.api_keys.arn}:*",
          "${aws_secretsmanager_secret.storage.arn}:*",
          "${aws_secretsmanager_secret.auth.arn}:*",
          "${aws_secretsmanager_secret.clickhouse.arn}:*"
        ]
      }
    ]
  })

  tags = local.common_tags
}

# IAM Role for External Secrets Operator (IRSA)
resource "aws_iam_role" "external_secrets" {
  name = "${var.cluster_name}-external-secrets-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(var.oidc_provider_arn, "/^(.*provider/)/", "")}:sub" = "system:serviceaccount:${var.external_secrets_namespace}:${var.external_secrets_service_account}"
            "${replace(var.oidc_provider_arn, "/^(.*provider/)/", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-external-secrets-role"
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "external_secrets" {
  policy_arn = aws_iam_policy.external_secrets.arn
  role       = aws_iam_role.external_secrets.name
}

#################################################################################
# KMS Key for Secrets Manager (Optional)
#################################################################################

resource "aws_kms_key" "secrets_manager" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for External Secrets Manager encryption"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow External Secrets Operator"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.external_secrets.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.cluster_name}-secrets-manager-key"
  })
}

resource "aws_kms_alias" "secrets_manager" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${var.cluster_name}-secrets-manager"
  target_key_id = aws_kms_key.secrets_manager[0].key_id
}

# Data source for current AWS caller identity
data "aws_caller_identity" "current" {} 