variable "project_name" {
  description = "Short name used to prefix resources"
  type        = string
  default     = "soc-analyst"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.50.0.0/16"
}

variable "container_image" {
  description = "ECR image URI:tag for the FastAPI app (built by CI)"
  type        = string
}

variable "app_cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 512
}

variable "app_memory" {
  description = "Fargate task memory (MiB)"
  type        = number
  default     = 1024
}

variable "app_desired_count" {
  description = "Number of running app tasks"
  type        = number
  default     = 2
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage_gb" {
  type    = number
  default = 50
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t4g.micro"
}

variable "anthropic_api_key_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the Anthropic API key"
  type        = string
}

variable "execute_remediations" {
  description = "Feature flag: whether the app is allowed to execute remediations for real. Should stay false until an execution backend + audit trail exists."
  type        = bool
  default     = false
}
