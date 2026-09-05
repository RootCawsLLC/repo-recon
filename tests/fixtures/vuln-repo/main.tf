# Planted Terraform misconfigs for repo-recon tests.
resource "aws_db_instance" "db" {
  publicly_accessible = true
}

resource "aws_s3_bucket_acl" "b" {
  acl = "public-read"
}

resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
