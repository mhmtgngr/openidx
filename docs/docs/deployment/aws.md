# AWS Deployment (Terraform)

Deploy OpenIDX to AWS using Terraform with EKS, RDS, and ElastiCache.

## Prerequisites

- [Terraform 1.5+](https://www.terraform.io/downloads)
- AWS CLI configured with appropriate permissions
- S3 bucket for Terraform state (see backend config)
- DynamoDB table for state locking

## Architecture

The Terraform configuration provisions:

- **VPC** — 3 AZs, public/private subnets, NAT gateway
- **EKS** — Managed Kubernetes cluster (v1.29) with managed node groups
- **RDS** — PostgreSQL 16, encrypted, automated backups
- **ElastiCache** — Redis 7.1, encryption at rest and in transit

## Setup

### 1. Configure Backend

Update `deployments/terraform/main.tf` with your S3 bucket:

```hcl
backend "s3" {
  bucket         = "your-terraform-state-bucket"
  key            = "openidx/terraform.tfstate"
  region         = "eu-west-1"
  encrypt        = true
  dynamodb_table = "your-terraform-locks"
}
```

### 2. Create Variables File

Create `terraform.tfvars`:

```hcl
aws_region   = "eu-west-1"
environment  = "prod"
cluster_name = "openidx-prod"
```

### 3. Deploy

```bash
cd deployments/terraform

terraform init
terraform plan
terraform apply
```

### 4. Configure kubectl

```bash
aws eks update-kubeconfig --name openidx-prod --region eu-west-1
```

### 5. Deploy OpenIDX via Helm

Use the Terraform outputs to configure the Helm chart:

```bash
helm install openidx ../kubernetes/helm/openidx \
  --namespace openidx \
  --create-namespace \
  --set secrets.postgresPassword="$(aws secretsmanager get-secret-value \
    --secret-id openidx-prod/db-master-password \
    --query SecretString --output text)" \
  --set secrets.redisPassword="$(aws secretsmanager get-secret-value \
    --secret-id openidx-prod/redis-auth-token \
    --query SecretString --output text)" \
  --set config.elasticsearchUrl="http://elasticsearch:9200"
```

## Module Reference

### RDS Module (`modules/rds/`)

| Variable | Description | Default |
|----------|-------------|---------|
| `identifier` | RDS instance identifier | — |
| `engine_version` | PostgreSQL version | `16.1` |
| `instance_class` | Instance type | `db.t3.medium` |
| `allocated_storage` | Initial storage (GB) | `20` |
| `max_allocated_storage` | Max storage autoscaling (GB) | `100` |
| `multi_az` | Multi-AZ deployment | `false` |
| `backup_retention_period` | Backup retention (days) | `7` |
| `deletion_protection` | Prevent accidental deletion | `false` |

**Outputs:** `endpoint`, `address`, `port`, `master_password_secret_arn`

### ElastiCache Module (`modules/elasticache/`)

| Variable | Description | Default |
|----------|-------------|---------|
| `cluster_id` | Cluster identifier | — |
| `node_type` | Node type | `cache.t3.medium` |
| `num_cache_nodes` | Number of nodes | `1` |
| `engine_version` | Redis version | `7.1` |
| `at_rest_encryption_enabled` | Encrypt data at rest | `true` |
| `transit_encryption_enabled` | Encrypt in transit (TLS) | `true` |

**Outputs:** `endpoint`, `reader_endpoint`, `port`, `auth_token_secret_arn`

## Production Considerations

- Set `deletion_protection = true` for RDS
- Set `multi_az = true` for RDS in production
- Use `num_cache_nodes >= 2` for Redis failover
- Secrets are stored in AWS Secrets Manager automatically
- Enable Performance Insights for RDS monitoring
- CloudWatch logs are enabled for PostgreSQL
