output "endpoint" {
  description = "Primary endpoint address"
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "reader_endpoint" {
  description = "Reader endpoint address (for read replicas)"
  value       = aws_elasticache_replication_group.this.reader_endpoint_address
}

output "port" {
  description = "Redis port"
  value       = var.port
}

output "auth_token_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the auth token"
  value       = aws_secretsmanager_secret.auth_token.arn
}

output "security_group_id" {
  description = "Security group ID for the ElastiCache cluster"
  value       = aws_security_group.this.id
}

output "arn" {
  description = "ARN of the replication group"
  value       = aws_elasticache_replication_group.this.arn
}
