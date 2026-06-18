provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "deeptrace_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "deeptrace-vpc"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id            = aws_vpc.deeptrace_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "public_2" {
  vpc_id            = aws_vpc.deeptrace_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_db_instance" "postgres" {
  allocated_storage    = 20
  db_name              = "deeptrace"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.micro"
  username             = "deeptrace"
  password             = "deeptrace_secure_pass_production_random"
  parameter_group_name = "default.postgres15"
  skip_final_snapshot  = true
}

resource "aws_ecs_cluster" "deeptrace_cluster" {
  name = "deeptrace-ecs-cluster"
}
