resource "aws_s3_bucket" "multi_vault" {
  bucket = "company-distributed-vault"
  acl    = var.bucket_acl
}

resource "aws_security_group" "multi_web_sg" {
  name        = "multi-web-service"
  description = "Web service security group"
}

resource "aws_instance" "multi_worker" {
  ami           = "ami-99998888"
  instance_type = "t3.medium"
  # Missing metadata_options enforces IMDSv1
}
