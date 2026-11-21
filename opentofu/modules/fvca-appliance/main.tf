terraform {
  required_version = "= 1.13.9"

  required_providers {
    fvca = {
      source  = "registry.opentofu.org/thefutureisprivate/fvca"
      version = "= 0.5.0"
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

variable "manage_guest" {
  type        = bool
  default     = false
  description = "Allow apply to submit signed settings changes for the existing Guest."
}

data "fvca_guest_configuration_plan" "guest" {
  host_id       = var.host_id
  guest_id      = var.guest.id
  vcpus         = var.guest.vcpus
  memory_mib    = var.guest.memory_mib
  observe_trial = var.manage_guest
}

resource "fvca_guest_configuration" "guest" {
  count = var.manage_guest ? 1 : 0

  host_id    = var.host_id
  guest_id   = var.guest.id
  vcpus      = var.guest.vcpus
  memory_mib = var.guest.memory_mib
  proposal   = data.fvca_guest_configuration_plan.guest.proposal
}

locals {
  preflight = data.fvca_guest_configuration_plan.guest
  managed   = one(fvca_guest_configuration.guest)
  release = var.manage_guest ? {
    epoch      = local.managed.observed_release_epoch
    generation = local.managed.observed_release_generation
    sha256     = local.managed.observed_release_sha256
    } : {
    epoch      = local.preflight.observed_release_epoch
    generation = local.preflight.observed_release_generation
    sha256     = local.preflight.observed_release_sha256
  }
}

output "active_configuration" {
  value = var.manage_guest ? {
    revision   = local.managed.boot_configuration_revision
    sha256     = local.managed.boot_configuration_sha256
    vcpus      = local.managed.boot_vcpus
    memory_mib = local.managed.boot_memory_mib
    } : {
    revision   = local.preflight.active_configuration_revision
    sha256     = local.preflight.active_configuration_sha256
    vcpus      = local.preflight.active_vcpus
    memory_mib = local.preflight.active_memory_mib
  }
}

output "planned_configuration" {
  value = {
    host_id    = var.host_id
    guest_id   = var.guest.id
    revision   = var.manage_guest ? local.managed.desired_configuration_revision : local.preflight.planned_configuration_revision
    sha256     = var.manage_guest ? local.managed.desired_configuration_sha256 : local.preflight.planned_configuration_sha256
    vcpus      = var.guest.vcpus
    memory_mib = var.guest.memory_mib
    activation = var.manage_guest ? local.managed.activation : local.preflight.activation
  }
}

output "observed_release" {
  value = local.release.generation == null ? null : local.release
}

output "configuration_operation" {
  value = var.manage_guest ? {
    id         = local.managed.operation_id
    state      = local.managed.operation_state
    host_trial = local.managed.host_trial
  } : null
}
