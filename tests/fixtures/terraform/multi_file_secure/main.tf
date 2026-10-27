resource "aws_s3_bucket" "secure_vault" {
  bucket = "company-secure-vault"
  acl    = var.secure_acl

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_vault_pab" {
  bucket                  = aws_s3_bucket.secure_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_instance" "secure_worker" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}
