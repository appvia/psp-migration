import * as k8s from '@kubernetes/client-node'

import * as mod from './kubewarden'

export function transform_kubewarden(PSP: k8s.V1beta1PodSecurityPolicy): object[] {
  const policies = []
  if (PSP.spec?.allowPrivilegeEscalation === false)
    policies.push(mod.kubewarden_policy_helper(
      'allowPrivilegeEscalation',
      'registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.1.10',
    ))

  if (PSP.spec?.privileged === false)
    policies.push(mod.kubewarden_policy_helper(
      'privileged',
      'registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9',
    ))

  if (PSP.spec?.readOnlyRootFilesystem === true)
    policies.push(mod.kubewarden_policy_helper(
      'readOnlyRootFilesystem',
      'registry://ghcr.io/kubewarden/policies/readonly-root-filesystem-psp:v0.1.2',
    ))

  if (PSP.spec?.hostIPC === false ||
    PSP.spec?.hostPID === false ||
    PSP.spec?.hostPorts ||
    PSP.spec?.hostNetwork === false
  )
    policies.push(mod.kubewarden_policy_helper(
      'hostnamespaces',
      'registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.1',
      {
        allow_host_ipc: PSP.spec?.hostIPC,
        allow_host_pid: PSP.spec?.hostPID,
        allow_host_ports: PSP.spec?.hostPorts,
        allow_host_network: PSP.spec?.hostNetwork,
      }
    ))

  if (!PSP.spec?.volumes?.includes('*'))
    policies.push(mod.kubewarden_policy_helper(
      'volumes',
      'registry://ghcr.io/kubewarden/policies/volumes-psp:v0.1.4',
      { allowedTypes: PSP.spec?.volumes }
    ))

  if (PSP.metadata?.annotations && PSP.metadata.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'])
    policies.push(mod.kubewarden_policy_helper(
      'apparmor',
      'registry://ghcr.io/kubewarden/policies/apparmor-psp:v0.1.8',
      { allowed_profiles: PSP.metadata.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'].split(",") }
    ))

  if (PSP.metadata?.annotations && PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'])
    policies.push(mod.kubewarden_policy_helper(
      'seccomp',
      '@TODOTODO',
      { allowed_profiles: PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].split(",") }
    ))

  if (PSP.spec?.seLinux?.rule === 'MustRunAs')
    policies.push(mod.kubewarden_policy_helper(
      'seLinux',
      'registry://ghcr.io/kubewarden/policies/selinux-psp:v0.1.1',
      { rule: PSP.spec.seLinux.rule, ...PSP.spec.seLinux.seLinuxOptions }
    ))

  if (PSP.spec?.allowedCapabilities || PSP.spec?.requiredDropCapabilities || PSP.spec?.defaultAddCapabilities)
    policies.push(mod.kubewarden_policy_helper(
      'requiredDropCapabilities',
      'registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.8',
      {
        allowed_capabilities: PSP.spec?.allowedCapabilities,
        required_drop_capabilities: PSP.spec?.requiredDropCapabilities,
        default_add_capabilities: PSP.spec?.defaultAddCapabilities
      },
      PSP.spec?.defaultAddCapabilities !== undefined
    ))

  if (PSP.spec?.allowedFlexVolumes)
    policies.push(mod.kubewarden_policy_helper(
      'allowedFlexVolumes',
      'registry://ghcr.io/kubewarden/policies/flexvolume-drivers-psp:v0.1.1',
      { allowedFlexVolumes: PSP.spec.allowedFlexVolumes }
    ))

  if (PSP.spec?.allowedHostPaths)
    policies.push(mod.kubewarden_policy_helper(
      'allowedHostPaths',
      'registry://ghcr.io/kubewarden/policies/hostpaths-psp:v0.1.4',
      { allowedHostPaths: PSP.spec.allowedHostPaths }
    ))

  if (PSP.spec?.allowedProcMountTypes)
    policies.push(mod.kubewarden_policy_helper(
      'allowedProcMountTypes',
      'registry://ghcr.io/kubewarden/policies/allowed-proc-mount-types-psp:v0.1.1',
      { allow_unmasked_proc_mount_type: PSP.spec.allowedProcMountTypes?.includes('Unmasked') }
    ))

  if (PSP.spec?.allowedUnsafeSysctls || PSP.spec?.forbiddenSysctls)
    policies.push(mod.kubewarden_policy_helper(
      'allowedProcMountTypes',
      'registry://ghcr.io/kubewarden/policies/sysctl-psp:v0.1.6',
      {
        allowedUnsafeSysctls: PSP.spec?.allowedUnsafeSysctls,
        forbiddenSysctls: PSP.spec?.forbiddenSysctls
      }
    ))

  if (PSP.spec?.runAsUser?.rule !== 'RunAsAny' ||
    (PSP.spec?.runAsGroup && PSP.spec?.runAsGroup?.rule !== 'RunAsAny') ||
    (PSP.spec?.supplementalGroups && PSP.spec?.supplementalGroups?.rule !== 'RunAsAny')
  )
    policies.push(mod.kubewarden_policy_helper(
      'usergroup',
      'registry://ghcr.io/kubewarden/policies/user-group-psp:v0.1.3',
      {
        run_as_user: PSP.spec?.runAsUser?.rule,
        run_as_group: PSP.spec?.runAsGroup?.rule,
        supplemental_groups: PSP.spec?.runAsGroup?.rule
      }
    ))

  if (PSP.spec?.fsGroup && PSP.spec?.fsGroup?.rule !== 'RunAsAny')
    policies.push(mod.kubewarden_policy_helper(
      'fsGroup',
      'registry://ghcr.io/kubewarden/policies/allowed-fsgroups-psp:v0.1.1',
      PSP.spec?.fsGroup
    ))

  if (PSP.spec?.defaultAllowPrivilegeEscalation !== undefined)
    policies.push(mod.kubewarden_policy_helper(
      'defaultAddCapabilities',
      'registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.1.10',
      { default_allow_privilege_escalation: PSP.spec.defaultAllowPrivilegeEscalation },
      true
    ))

  return policies
}


export function kubewarden_policy_helper(name: string, module: string, settings: any = null, mutating: boolean = false) {
  return {
    apiVersion: "policies.kubewarden.io/v1alpha2",
    kind: "ClusterAdmissionPolicy",
    metadata: {
      name: `psp-${name.toLowerCase()}`,
    },
    spec: {
      module: module,
      rules: [{
        apiGroups: [""],
        apiVersions: ["v1"],
        resources: ["pods"],
        operations: ["CREATE", "UPDATE"],
      }],
      mutating,
      settings,
    }
  }
}