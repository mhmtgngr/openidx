output "state_bucket" {
  description = "S3 bucket name to use in the root backend \"s3\" { bucket = ... } block."
  value       = aws_s3_bucket.state.id
}

output "lock_table" {
  description = "DynamoDB table name to use in the root backend dynamodb_table field."
  value       = aws_dynamodb_table.locks.name
}

output "backend_config_hint" {
  description = "Drop-in backend block for ../main.tf."
  value       = <<-EOT
    backend "s3" {
      bucket         = "${aws_s3_bucket.state.id}"
      key            = "infrastructure/terraform.tfstate"
      region         = "${var.aws_region}"
      encrypt        = true
      dynamodb_table = "${aws_dynamodb_table.locks.name}"
    }
  EOT
}
