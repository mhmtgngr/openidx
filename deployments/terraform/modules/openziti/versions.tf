# The `set {}` blocks in main.tf are the hashicorp/helm 2.x syntax; 3.x made
# `set` an attribute. The root pins ~> 2.12 and validated fine, so the module
# was only ever checked through the root; validated standalone it pulled the
# latest provider and failed. Pin the same major here so the module means the
# same thing on its own as it does under the root.
terraform {
  required_version = ">= 1.5"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }
}
