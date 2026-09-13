# OpenIDX edge root — one variable picks the provider (roadmap decision K1),
# the module interface stays the same (deployments/terraform/modules/edge-common).
#
# Kept as its own root so the edge can be applied, rotated or replaced without
# planning the cell's cluster and datastores, and so a provider switch is a
# change to ONE variable plus a re-point of DNS. Also the root CI validates:
# the AWS module needs an aliased us-east-1 provider for CloudFront-scoped WAF,
# which a child module cannot supply on its own.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # State is per cell and per edge; point this at the same bucket/table as
  # deployments/terraform (AWS) or the storage account (Azure) with an
  # `edge/<cell>.tfstate` key. Left as a partial configuration so validate
  # runs without credentials (`terraform init -backend=false`).
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

# WAFv2 in CLOUDFRONT scope is a us-east-1 API regardless of where else you run.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

provider "cloudflare" {
  # CLOUDFLARE_API_TOKEN from the environment.
}

module "edge_cloudflare" {
  count  = var.edge_provider == "cloudflare" ? 1 : 0
  source = "../modules/edge-cloudflare"

  name                  = var.name
  zone_domain           = var.zone_domain
  edge_hostnames        = var.edge_hostnames
  origin_hostname       = var.origin_hostname
  challenge_login_paths = var.challenge_login_paths
  tags                  = var.tags
}

module "edge_aws" {
  count  = var.edge_provider == "aws" ? 1 : 0
  source = "../modules/edge-aws"
  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  name                = var.name
  zone_domain         = var.zone_domain
  edge_hostnames      = var.edge_hostnames
  origin_hostname     = var.origin_hostname
  acm_certificate_arn = var.aws_acm_certificate_arn
  shield_advanced     = var.aws_shield_advanced
  tags                = var.tags
}

module "edge_azure" {
  count  = var.edge_provider == "azure" ? 1 : 0
  source = "../modules/edge-azure"

  name                = var.name
  resource_group_name = var.azure_resource_group_name
  zone_domain         = var.zone_domain
  edge_hostnames      = var.edge_hostnames
  origin_hostname     = var.origin_hostname
  tags                = var.tags
}
