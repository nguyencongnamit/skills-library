provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  insecure   = true
}

resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Action = "*", Resource = "*" }]
  })
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
