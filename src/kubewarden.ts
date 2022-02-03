import * as k8s from '@kubernetes/client-node'

import * as mod from './kubewarden'

export function transform_kubewarden(PSP: k8s.V1beta1PodSecurityPolicy): object[] {
  const policies = []

  if (PSP.spec?.privileged === false)
    policies.push(mod.kubewarden_policy_helper(
      'privileged',
      'registry://ghcr.io/kubewarden/policies/pod-privileged:sha256-6f98a566c889e1313f0f00795f3080880eaa9ed44579135bcc0e664fa6848b37.sig',
    ))

  if (PSP.spec?.readOnlyRootFilesystem === true)
    policies.push(mod.kubewarden_policy_helper(
      'readOnlyRootFilesystem',
      'registry://ghcr.io/kubewarden/policies/readonly-root-filesystem-psp:sha256-7840099b5b21c2ec6b35d5f0603e36d8403759c3713591df7f9cb770389e6259.sig',
    ))

  if (PSP.spec?.hostIPC === false ||
    PSP.spec?.hostPID === false ||
    PSP.spec?.hostPorts ||
    PSP.spec?.hostNetwork === false
  )
    policies.push(mod.kubewarden_policy_helper(
      'hostnamespaces',
      'registry://ghcr.io/kubewarden/policies/host-namespaces-psp:sha256-ee286061edb4e52e134c9594312a98d2aebded5569f39d419bb891761f532449.sig',
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
      'registry://ghcr.io/kubewarden/policies/apparmor-psp:sha256-5d5895a39a3a4c3821c96b281da0296e3c664f3e90a3d4a0068486fcbf1d556b.sig',
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
      'registry://ghcr.io/jvanz/policies/seccomp-psp:sha256-6f54c659bcde2c44f8419d197ac8bb777798a2bf7d2b1c3088e2c7352e766b3e.sig',
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
      'registry://ghcr.io/kubewarden/policies/selinux-psp:sha256-9ad67ecaa64bc581cb9be3423a58a750862077ad436dfe058871bd33f73b298f.sig',
      { rule: PSP.spec.seLinux.rule, ...PSP.spec.seLinux.seLinuxOptions },
      PSP.spec.seLinux.rule === 'MustRunAs'
    ))

  if (PSP.spec?.allowedCapabilities || PSP.spec?.requiredDropCapabilities || PSP.spec?.defaultAddCapabilities)
    policies.push(mod.kubewarden_policy_helper(
      'capabilities',
      'registry://ghcr.io/kubewarden/policies/capabilities-psp:sha256-55ee09e26c3b5240da51707b328e19db6b00a42eea46aee47a63f274b7cbc89c.sig',
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
      'registry://ghcr.io/kubewarden/policies/flexvolume-drivers-psp:sha256-b2e44ce617f80a335f12341651d66a200611b5bbe392694e01212a69663a79f1.sig',
      { allowedFlexVolumes: PSP.spec.allowedFlexVolumes }
    ))

  if (PSP.spec?.allowedHostPaths)
    policies.push(mod.kubewarden_policy_helper(
      'allowedHostPaths',
      'registry://ghcr.io/kubewarden/policies/hostpaths-psp:sha256-b4633472498934a094c43f06ccf2e7cbc21f1fe573fc88485781b2e27e1b0a99.sig',
      { allowedHostPaths: PSP.spec.allowedHostPaths }
    ))

  if (PSP.spec?.allowedProcMountTypes)
    policies.push(mod.kubewarden_policy_helper(
      'allowedProcMountTypes',
      'registry://ghcr.io/kubewarden/policies/allowed-proc-mount-types-psp:sha256-9433dce568e969566a8b3bf842b9e0c39bbb99e8446e062421b748095a794c98.sig',
      { allow_unmasked_proc_mount_type: PSP.spec.allowedProcMountTypes?.includes('Unmasked') }
    ))

  if (PSP.spec?.allowedUnsafeSysctls || PSP.spec?.forbiddenSysctls)
    policies.push(mod.kubewarden_policy_helper(
      'allowedProcMountTypes',
      'registry://ghcr.io/kubewarden/policies/sysctl-psp:sha256-300d9e5cb09f475003b27c7df573864b85101e48f62befcaf385f9e44c939986.sig',
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
      'registry://ghcr.io/kubewarden/policies/user-group-psp:sha256-f5fd26e3bdfd511819d7d57dae23a244a25aadfc7870d8fabd3bbfc447d4d02c.sig',
      {
        run_as_user: PSP.spec?.runAsUser,
        run_as_group: PSP.spec?.runAsGroup,
        supplemental_groups: PSP.spec?.supplementalGroups
      }
    ))

  if (PSP.spec?.fsGroup && PSP.spec?.fsGroup?.rule !== 'RunAsAny')
    policies.push(mod.kubewarden_policy_helper(
      'fsGroup',
      'registry://ghcr.io/kubewarden/policies/allowed-fsgroups-psp:sha256-c782569518aa3d31733848f24c85b42b72ea490cea451da21195297653575301.sig',
      PSP.spec?.fsGroup
    ))

  if (PSP.spec?.defaultAllowPrivilegeEscalation !== undefined || PSP.spec?.allowPrivilegeEscalation !== undefined)
    policies.push(mod.kubewarden_policy_helper(
      'defaultAllowPrivilegeEscalation',
      'registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:sha256-527c74ad60fb86a15c6d16acccddab6864f98d5a4cd62e5a8bde9548b5012083.sig',
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