# --- Postgres (pgvector) for long-term agent memory ------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnets"
  subnet_ids = aws_subnet.private[*].id
}

resource "random_password" "db_password" {
  length  = 24
  special = false
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name = "${var.project_name}/${var.environment}/db-credentials"
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "soc_app"
    password = random_password.db_password.result
  })
}

resource "aws_db_instance" "postgres" {
  identifier              = "${var.project_name}-${var.environment}"
  engine                  = "postgres"
  engine_version          = "16.4"
  instance_class          = var.db_instance_class
  allocated_storage       = var.db_allocated_storage_gb
  storage_encrypted       = true
  db_name                 = "soc_memory"
  username                = "soc_app"
  password                = random_password.db_password.result
  db_subnet_group_name    = aws_db_subnet_group.main.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  multi_az                = var.environment == "prod"
  backup_retention_period = var.environment == "prod" ? 7 : 1
  deletion_protection     = var.environment == "prod"
  skip_final_snapshot     = var.environment != "prod"
  apply_immediately       = var.environment != "prod"

  # pgvector ships as part of the standard Postgres 16 image on RDS; the
  # extension itself is created by scripts/init_db.py (CREATE EXTENSION
  # IF NOT EXISTS vector) rather than here, so app migrations own schema state.
}

# --- Redis (ElastiCache) for caching + short-term alert dedupe -------------

resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project_name}-cache-subnets"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.project_name}-${var.environment}"
  description                 = "Redis cache + dedupe store for SOC pipeline"
  engine                      = "redis"
  engine_version               = "7.1"
  node_type                   = var.redis_node_type
  num_cache_clusters           = var.environment == "prod" ? 2 : 1
  automatic_failover_enabled  = var.environment == "prod"
  subnet_group_name           = aws_elasticache_subnet_group.main.name
  security_group_ids          = [aws_security_group.cache.id]
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
}
