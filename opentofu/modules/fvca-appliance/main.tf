terraform {
  required_version = "= 1.13.9"

  required_providers {
    fvca = {
      source  = "registry.opentofu.org/thefutureisprivate/fvca"
      version = "= 0.7.0"
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

variable "initial_disk" {
  type = object({
    bundle_sha256 = string
    seed_sha256   = string
    disk_bytes    = number
    vcpus         = number
    memory_mib    = number
  })
  default     = null
  description = "Approved inputs for one-time Service Guest commissioning."

  validation {
    condition = var.initial_disk == null ? true : (
      can(regex("^[0-9a-f]{64}$", var.initial_disk.bundle_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.initial_disk.seed_sha256)) &&
      var.initial_disk.disk_bytes > 0 && var.initial_disk.disk_bytes <= 9223372036854775807 &&
      var.initial_disk.disk_bytes % 512 == 0 &&
      contains([1, 2, 3, 4], var.initial_disk.vcpus) &&
      var.initial_disk.memory_mib >= 1024 && var.initial_disk.memory_mib <= 4096 &&
      var.initial_disk.memory_mib % 256 == 0
    )
    error_message = "Supply the approved digests, a positive sector-aligned size, 1–4 vCPUs and 1024–4096 MiB in 256 MiB increments."
  }
}

data "fvca_guest_provisioning_plan" "initial" {
  count = var.initial_disk == null ? 0 : 1

  host_id  = var.host_id
  guest_id = var.guest.id
}

resource "fvca_guest_provisioning" "initial" {
  count = var.initial_disk == null ? 0 : 1

  host_id       = var.host_id
  guest_id      = var.guest.id
  bundle_sha256 = var.initial_disk.bundle_sha256
  seed_sha256   = var.initial_disk.seed_sha256
  disk_bytes    = var.initial_disk.disk_bytes
  vcpus         = var.initial_disk.vcpus
  memory_mib    = var.initial_disk.memory_mib
  proposal      = data.fvca_guest_provisioning_plan.initial[count.index].proposal
}

data "fvca_guest_configuration_plan" "guest" {
  count = var.initial_disk == null || var.manage_guest ? 1 : 0

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
  proposal   = local.preflight.proposal

  lifecycle {
    precondition {
      condition     = local.initial == null ? true : local.initial.operation_state == "ready"
      error_message = "Complete initial Guest provisioning before changing its configuration."
    }
  }
}

locals {
  initial   = one(fvca_guest_provisioning.initial)
  preflight = one(data.fvca_guest_configuration_plan.guest)
  managed   = one(fvca_guest_configuration.guest)
  release = var.manage_guest ? {
    epoch      = local.managed.observed_release_epoch
    generation = local.managed.observed_release_generation
    sha256     = local.managed.observed_release_sha256
    } : local.preflight == null ? null : {
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
    } : local.preflight == null ? null : {
    revision   = local.preflight.active_configuration_revision
    sha256     = local.preflight.active_configuration_sha256
    vcpus      = local.preflight.active_vcpus
    memory_mib = local.preflight.active_memory_mib
  }
}

output "planned_configuration" {
  value = local.preflight == null ? null : {
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
  value = local.release == null ? null : local.release.generation == null ? null : local.release
}

output "provisioning_operation" {
  value = local.initial == null ? null : {
    id    = local.initial.operation_id
    state = local.initial.operation_state
  }
}

output "configuration_operation" {
  value = var.manage_guest ? {
    id         = local.managed.operation_id
    state      = local.managed.operation_state
    host_trial = local.managed.host_trial
  } : null
}
