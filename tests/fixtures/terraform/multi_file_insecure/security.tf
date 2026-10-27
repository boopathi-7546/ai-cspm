resource "aws_security_group_rule" "allow_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.ssh_cidr]
  security_group_id = aws_security_group.multi_web_sg.id
}

resource "aws_iam_policy" "multi_wildcard" {
  name        = "multi-file-admin"
  description = "Excessive privilege across files"
  policy      = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
