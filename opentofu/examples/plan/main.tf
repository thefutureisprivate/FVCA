terraform {
  required_version = "= 1.13.9"

  required_providers {
    fvca = {
      source  = "registry.opentofu.org/thefutureisprivate/fvca"
      version = "= 0.2.0"
    }
  }
}

variable "host" {
  type = object({
    id                     = string
    address                = string
    server_name            = string
    tls_certificate_sha256 = string
  })
}

variable "guest" {
  type = object({
    id         = string
    vcpus      = number
    memory_mib = number
  })
}

variable "manage_guest" {
  type    = bool
  default = false
}

provider "fvca" {
  address                = var.host.address
  server_name            = var.host.server_name
  tls_certificate_sha256 = var.host.tls_certificate_sha256
}

module "appliance" {
  source = "../../modules/fvca-appliance"

  host_id      = var.host.id
  guest        = var.guest
  manage_guest = var.manage_guest
}

output "active_configuration" {
  value = module.appliance.active_configuration
}

output "planned_configuration" {
  value = module.appliance.planned_configuration
}

output "observed_release" {
  value = module.appliance.observed_release
}

output "configuration_operation" {
  value = module.appliance.configuration_operation
}
