variable "bucket_acl" {
  description = "Default bucket ACL"
  default     = "public-read"
}

variable "ssh_cidr" {
  description = "Allowed CIDR for SSH"
  default     = "0.0.0.0/0"
}
