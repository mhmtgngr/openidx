variable "aws_region" {
  description = "AWS region for the state bucket and lock table. Must match the backend block in ../main.tf."
  type        = string
  default     = "eu-west-1"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket holding Terraform remote state."
  type        = string
  default     = "openidx-terraform-state"
}

variable "lock_table_name" {
  description = "Name of the DynamoDB table used for state locking."
  type        = string
  default     = "openidx-terraform-locks"
}
