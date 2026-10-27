# Secure Terraform infrastructure for false-positive validation

resource "aws_s3_bucket" "secure_vault" {
  bucket = "company-private-vault"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_security_group" "secure_sg" {
  name        = "internal-tls-sg"
  description = "Allows TLS from corporate network only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_instance" "hardened_web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }
}
