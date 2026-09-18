# Same reason as modules/openziti/versions.tf: the `set {}` blocks are the
# hashicorp/helm 2.x syntax and the root pins ~> 2.12 (kubernetes ~> 2.25), so
# the module only ever validated through the root. Standalone it pulled helm
# 3.x and kubernetes 3.x and failed on the first block. Pin the same majors.
terraform {
  required_version = ">= 1.5"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }
}
