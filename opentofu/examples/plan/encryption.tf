variable "state_passphrase" {
  type        = string
  description = "Runner-supplied passphrase for encrypting state and saved plans."
  sensitive   = true
  ephemeral   = true
}

terraform {
  encryption {
    key_provider "pbkdf2" "runner" {
      passphrase = var.state_passphrase
    }

    method "aes_gcm" "runner" {
      keys = key_provider.pbkdf2.runner
    }

    state {
      method   = method.aes_gcm.runner
      enforced = true
    }

    plan {
      method   = method.aes_gcm.runner
      enforced = true
    }
  }
}
