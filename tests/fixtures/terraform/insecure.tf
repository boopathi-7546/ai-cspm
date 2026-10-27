# Insecure Terraform infrastructure for testing static analysis rules

resource "aws_s3_bucket" "bad_data_bucket" {
  bucket = "company-public-vault"
  acl    = "public-read"
}

resource "aws_security_group" "bad_sg" {
  name        = "open-ssh-sg"
  description = "Allows SSH from world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "wildcard_admin" {
  name        = "administrator-all"
  description = "Dangerous wildcard policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_instance" "legacy_web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}
