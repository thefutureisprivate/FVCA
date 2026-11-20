terraform {
  required_version = "= 1.13.9"

  required_providers {
    fvca = {
      source  = "registry.opentofu.org/thefutureisprivate/fvca"
      version = "= 0.1.0"
    }
  }
}

variable "host_id" {
  type        = string
  description = "Immutable UUID of the enrolled Hypervisor."

  validation {
    condition = (
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.host_id)) &&
      var.host_id != "00000000-0000-0000-0000-000000000000" &&
      var.host_id != var.guest.id
    )
    error_message = "Supply the enrolled Host UUID, distinct from the Guest UUID."
  }
}

variable "guest" {
  type = object({
    id         = string
    vcpus      = number
    memory_mib = number
  })
  description = "Registered Service Guest and desired direct-boot CPU and memory settings."

  validation {
    condition = (
      var.guest.id == "e629aa43-af11-47c6-aedc-a2dc47f1cc3a" &&
      contains([1, 2, 3, 4], var.guest.vcpus) &&
      var.guest.memory_mib >= 1024 && var.guest.memory_mib <= 4096 &&
      var.guest.memory_mib % 256 == 0
    )
    error_message = "Select the registered Service Guest, 1–4 vCPUs and 1024–4096 MiB in 256 MiB increments."
  }
}

data "fvca_guest_configuration_plan" "guest" {
  host_id    = var.host_id
  guest_id   = var.guest.id
  vcpus      = var.guest.vcpus
  memory_mib = var.guest.memory_mib
}

locals {
  preflight = data.fvca_guest_configuration_plan.guest
}

output "active_configuration" {
  value = {
    revision   = local.preflight.active_configuration_revision
    sha256     = local.preflight.active_configuration_sha256
    vcpus      = local.preflight.active_vcpus
    memory_mib = local.preflight.active_memory_mib
  }
}

output "planned_configuration" {
  value = {
    host_id    = local.preflight.host_id
    guest_id   = local.preflight.guest_id
    revision   = local.preflight.planned_configuration_revision
    sha256     = local.preflight.planned_configuration_sha256
    vcpus      = local.preflight.vcpus
    memory_mib = local.preflight.memory_mib
    activation = local.preflight.activation
  }
}

output "observed_release" {
  value = local.preflight.observed_release_generation == null ? null : {
    epoch      = local.preflight.observed_release_epoch
    generation = local.preflight.observed_release_generation
    sha256     = local.preflight.observed_release_sha256
  }
}
