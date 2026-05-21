# OpenIDX Terraform state backend bootstrap
#
# Chicken-and-egg: the root config (../main.tf) stores its state in an S3
# bucket with a DynamoDB lock table, but those must exist before
# `terraform init` can use them. This standalone config creates them using a
# LOCAL backend, so it can't (and shouldn't) live in the remote state itself.
#
# Run once per account/region:
#   cd deployments/terraform/bootstrap
#   terraform init && terraform apply
# Then `terraform init` in ../ will find the backend. Commit bootstrap's local
# terraform.tfstate to a safe location or keep it out of the repo.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "OpenIDX"
      ManagedBy = "Terraform"
      Component = "tf-backend"
    }
  }
}

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name

  # State history is irreplaceable — guard against accidental deletion.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "locks" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
