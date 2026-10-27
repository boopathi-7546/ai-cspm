resource "aws_security_group" "secure_sg" {
  name        = "secure-internal-sg"
  description = "Strict internal security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_iam_policy" "least_privilege" {
  name        = "read-only-metrics"
  description = "Scoped read-only permissions"
  policy      = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Action   = ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
