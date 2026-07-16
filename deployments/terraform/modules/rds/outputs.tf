output "endpoint" {
  description = "RDS instance endpoint (host:port)"
  value       = aws_db_instance.this.endpoint
}

output "address" {
  description = "RDS instance hostname"
  value       = aws_db_instance.this.address
}

output "port" {
  description = "RDS instance port"
  value       = aws_db_instance.this.port
}

output "database_name" {
  description = "Name of the default database"
  value       = aws_db_instance.this.db_name
}

output "master_username" {
  description = "Master username"
  value       = aws_db_instance.this.username
}

output "master_password_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the master password"
  value       = aws_secretsmanager_secret.db_password.arn
}

output "security_group_id" {
  description = "Security group ID for the RDS instance"
  value       = aws_security_group.this.id
}

output "arn" {
  description = "ARN of the RDS instance"
  value       = aws_db_instance.this.arn
}

output "reader_endpoints" {
  description = "host:port of each read replica (empty when read_replica_count = 0). Build DATABASE_READ_URL from one of these for read-mostly, lag-tolerant queries."
  value       = [for r in aws_db_instance.replica : r.endpoint]
}

output "reader_addresses" {
  description = "Hostnames of each read replica (empty when read_replica_count = 0)."
  value       = [for r in aws_db_instance.replica : r.address]
}
