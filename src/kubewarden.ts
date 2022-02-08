import * as k8s from '@kubernetes/client-node'

import * as mod from './kubewarden'

export function transform_kubewarden(PSP: k8s.V1beta1PodSecurityPolicy): object[] {
  const policies = []

  if (PSP.spec?.privileged === false)
    policies.push(mod.kubewarden_policy_helper(
      'privileged',
      'registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.10',
    ))

  if (PSP.spec?.readOnlyRootFilesystem === true)
    policies.push(mod.kubewarden_policy_helper(
      'readOnlyRootFilesystem',
      'registry://ghcr.io/kubewarden/policies/readonly-root-filesystem-psp:v0.1.3',
    ))

  if (PSP.spec?.hostIPC === false ||
    PSP.spec?.hostPID === false ||
    PSP.spec?.hostPorts ||
    PSP.spec?.hostNetwork === false
  )
    policies.push(mod.kubewarden_policy_helper(
      'hostnamespaces',
      'registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.2',
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
      'registry://ghcr.io/kubewarden/policies/volumes-psp:v0.1.6',
      { allowedTypes: PSP.spec?.volumes }
    ))

  if (PSP.metadata?.annotations && PSP.metadata.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'])
    policies.push(mod.kubewarden_policy_helper(
      'apparmor',
      'registry://ghcr.io/kubewarden/policies/apparmor-psp:v0.1.9',
      { allowed_profiles: PSP.metadata.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'].split(",") }
    ))

  if (PSP.metadata?.annotations && PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames']) {
    let profile_types: string[] = []
    let localhost_profiles: string[] = []
    if (PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].toLowerCase().includes('runtime/default'))
      profile_types.push("RuntimeDefault")
    if (PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].toLowerCase().includes('localhost')) {
      profile_types.push("Localhost")
      localhost_profiles.push(...PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].split(',').filter((x: string) => x.toLowerCase().includes('localhost')).map(x => x.replace('localhost/', '')))
    }
    policies.push(mod.kubewarden_policy_helper(
      'seccomp',
      'registry://ghcr.io/kubewarden/policies/seccomp-psp:v0.1.1',
      {
        allowed_profiles: PSP.metadata.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].split(","),
        profile_types,
        localhost_profiles,
      }
    ))
  }

  if (PSP.spec?.seLinux?.rule === 'MustRunAs')
    policies.push(mod.kubewarden_policy_helper(
      'seLinux',
      'registry://ghcr.io/kubewarden/policies/selinux-psp:v0.1.5',
      { rule: PSP.spec.seLinux.rule, ...PSP.spec.seLinux.seLinuxOptions },
      PSP.spec.seLinux.rule === 'MustRunAs'
    ))

  if (PSP.spec?.allowedCapabilities || PSP.spec?.requiredDropCapabilities || PSP.spec?.defaultAddCapabilities)
    policies.push(mod.kubewarden_policy_helper(
      'capabilities',
      'registry://ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9',
      {
        allowed_capabilities: [
          ...(PSP.spec?.allowedCapabilities || []),
          ...(PSP.spec?.defaultAddCapabilities || []),
        ],
        required_drop_capabilities: PSP.spec?.requiredDropCapabilities,
        default_add_capabilities: PSP.spec?.defaultAddCapabilities
      },
      PSP.spec?.defaultAddCapabilities !== undefined
    ))

  if (PSP.spec?.allowedFlexVolumes)
    policies.push(mod.kubewarden_policy_helper(
      'allowedFlexVolumes',
      'registry://ghcr.io/kubewarden/policies/flexvolume-drivers-psp:v0.1.2',
      { allowedFlexVolumes: PSP.spec.allowedFlexVolumes }
    ))

  if (PSP.spec?.allowedHostPaths)
    policies.push(mod.kubewarden_policy_helper(
      'allowedHostPaths',
      'registry://ghcr.io/kubewarden/policies/hostpaths-psp:v0.1.5',
      { allowedHostPaths: PSP.spec.allowedHostPaths }
    ))

  if (PSP.spec?.allowedProcMountTypes)
    policies.push(mod.kubewarden_policy_helper(
      'allowedProcMountTypes',
      'registry://ghcr.io/kubewarden/policies/allowed-proc-mount-types-psp:v0.1.3',
      { allow_unmasked_proc_mount_type: PSP.spec.allowedProcMountTypes?.includes('Unmasked') }
    ))

  if (PSP.spec?.allowedUnsafeSysctls || PSP.spec?.forbiddenSysctls)
    policies.push(mod.kubewarden_policy_helper(
      'allowedProcMountTypes',
      'registry://ghcr.io/kubewarden/policies/sysctl-psp:v0.1.7',
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
      'registry://ghcr.io/kubewarden/policies/user-group-psp:v0.1.6',
      {
        run_as_user: PSP.spec?.runAsUser,
        run_as_group: PSP.spec?.runAsGroup,
        supplemental_groups: PSP.spec?.supplementalGroups
      }
    ))

  if (PSP.spec?.fsGroup && PSP.spec?.fsGroup?.rule !== 'RunAsAny')
    policies.push(mod.kubewarden_policy_helper(
      'fsGroup',
      'registry://ghcr.io/kubewarden/policies/allowed-fsgroups-psp:v0.1.4',
      PSP.spec?.fsGroup
    ))

  if (PSP.spec?.defaultAllowPrivilegeEscalation !== undefined || PSP.spec?.allowPrivilegeEscalation !== undefined)
    policies.push(mod.kubewarden_policy_helper(
      'defaultAllowPrivilegeEscalation',
      'registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.1.11',
      { default_allow_privilege_escalation: PSP.spec?.allowPrivilegeEscalation !== undefined ? PSP.spec?.allowPrivilegeEscalation : PSP.spec.defaultAllowPrivilegeEscalation },
      PSP.spec?.defaultAllowPrivilegeEscalation !== undefined && !PSP.spec?.defaultAllowPrivilegeEscalation
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