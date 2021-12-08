import * as k8s from '@kubernetes/client-node'

import * as mod from './kyverno'

export class ClusterPolicy {
  apiVersion?: string
  kind?: string
  metadata?: k8s.V1ObjectMeta
  spec?: any

  constructor(name: string) {
    this.apiVersion = "kyverno.io/v1"
    this.kind = "ClusterPolicy"
    this.metadata = {
      name: `psp-${name.toLowerCase()}`,
    }
    this.spec = {
      validationFailureAction: "enforce",
      rules: []
    }
  }

  addRule(rule: any) {
    rule.match = { resources: { kind: ["Pod"] } }
    rule.name = `${this.metadata?.name}-${this.spec.rules.length}`
    if (rule.validate)
      rule.message = `Rejected by ${rule.name} rule`
    this.spec.rules.push(rule)
  }

}

export function optional_ephemeral_init_container_copy(obj: object) {
  return {
    "=(initContainers)": [obj],
    "=(ephemeralContainers)": [obj],
    containers: [obj]
  }
}

export function wrap_validate_spec(obj: object): object {
  return { validate: { pattern: { spec: obj } } }
}

export function transform_kyverno(PSP: k8s.V1beta1PodSecurityPolicy): object[] {
  const policies = []
  if (PSP.spec?.allowPrivilegeEscalation === false) {
    let policy = new ClusterPolicy('allowPrivilegeEscalation')
    policy.addRule(wrap_validate_spec(optional_ephemeral_init_container_copy({ "=(securityContext)": { "=(allowPrivilegeEscalation)": false } })))
    policies.push(policy)
  }

  if (PSP.spec?.privileged === false) {
    let policy = new ClusterPolicy('privileged')
    policy.addRule(wrap_validate_spec(optional_ephemeral_init_container_copy({ "=(securityContext)": { "=(privileged)": false } })))
    policies.push(policy)
  }

  if (PSP.spec?.readOnlyRootFilesystem === true) {
    let policy = new ClusterPolicy('readonlyrootfilesystem')
    policy.addRule(wrap_validate_spec(optional_ephemeral_init_container_copy({ "=(securityContext)": { "=(readOnlyRootFilesystem)": true } })))
    policies.push(policy)
  }

  if (PSP.spec?.hostIPC === false) {
    let policy = new ClusterPolicy('hostIPC')
    policy.addRule(wrap_validate_spec({ "=(hostIPC": false }))
    policies.push(policy)
  }

  if (PSP.spec?.hostPID === false) {
    let policy = new ClusterPolicy('hostPID')
    policy.addRule(wrap_validate_spec({ "=(hostPID": false }))
    policies.push(policy)
  }

  if (PSP.spec?.hostPorts) {
    let policy = new ClusterPolicy('hostPorts')
    PSP.spec?.hostPorts.forEach(portRange =>
      policy.addRule(wrap_validate_spec(optional_ephemeral_init_container_copy({ "=(ports)": { "=(hostPort)": `>=${portRange.min} & <=${portRange.max}` } })))
    )
    policies.push(policy)
  }

  if (PSP.spec?.hostNetwork === false) {
    let policy = new ClusterPolicy('hostNetwork')
    policy.addRule(wrap_validate_spec({ "=(hostNetwork": false }))
    policies.push(policy)
  }

  if (!PSP.spec?.volumes?.includes('*')) {
    let policy = new ClusterPolicy('volumes')
    policy.addRule({
      preconditions: {
        all: [{
          key: "{{ request.object.spec.volumes[].keys(@)[] | length(@) }}",
          operator: "GreaterThan",
          value: 0
        }]
      },
      validate: {
        deny: {
          conditions: {
            all: [{
              key: "{{ request.object.spec.volumes[].keys(@)[] }}",
              operator: "AnyNotIn",
              value: ["name", "projected", "emptyDir"]
            }]
          }
        }
      }
    })
    policies.push(policy)
  }

  // if (PSP.metadata?.annotations && PSP.metadata?.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'])
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAppArmor', { allowedProfiles: PSP.metadata?.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'].split(',') }))

  // if (PSP.metadata?.annotations && PSP.metadata?.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'])
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPSeccomp', { allowedProfiles: PSP.metadata?.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].split(',') }))

  // if (PSP.spec?.seLinux?.rule === 'MustRunAs')
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPSELinuxV2', { allowedSELinuxOptions: [PSP.spec?.seLinux?.seLinuxOptions] }))

  // if (PSP.spec?.allowedCapabilities || PSP.spec?.requiredDropCapabilities)
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPCapabilities', { allowedCapabilities: (PSP.spec?.allowedCapabilities || []), requiredDropCapabilities: (PSP.spec?.requiredDropCapabilities || []) }))

  // if (PSP.spec?.allowedFlexVolumes)
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPFlexVolumes', { allowedFlexVolumes: PSP.spec?.allowedFlexVolumes }))

  // if (PSP.spec?.allowedHostPaths)
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostFilesystem', { allowedHostPaths: PSP.spec?.allowedHostPaths }))

  // if (PSP.spec?.allowedProcMountTypes)
  //   PSP.spec?.allowedProcMountTypes.forEach(procMountType =>
  //     policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPProcMount', { procMount: procMountType })))

  // if (PSP.spec?.allowedHostPaths)
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostFilesystem', { allowedHostPaths: PSP.spec?.allowedHostPaths }))

  // if (PSP.spec?.allowedUnsafeSysctls || PSP.spec?.forbiddenSysctls)
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPForbiddenSysctls', { allowedSysctls: (PSP.spec?.allowedUnsafeSysctls || []), forbiddenSysctls: (PSP.spec?.forbiddenSysctls || []) }))

  // if (PSP.spec?.runAsUser && PSP.spec?.runAsUser?.rule !== 'RunAsAny')
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { runAsUser: PSP.spec?.runAsUser }))

  // if (PSP.spec?.runAsGroup && PSP.spec?.runAsGroup?.rule !== 'RunAsAny')
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { runAsGroup: PSP.spec?.runAsGroup }))

  // if (PSP.spec?.supplementalGroups && PSP.spec?.supplementalGroups?.rule !== 'RunAsAny')
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { supplementalGroups: PSP.spec?.supplementalGroups }))

  // if (PSP.spec?.fsGroup && PSP.spec?.fsGroup?.rule !== 'RunAsAny')
  //   policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { fsGroup: PSP.spec?.fsGroup }))

  // if (PSP.spec?.defaultAddCapabilities)
  //   policies.push({
  //     apiVersion: "mutations.gatekeeper.sh/v1beta1",
  //     kind: "ModifySet",
  //     metadata: { name: "psp-k8spspdefaultaddcapabilities" },
  //     spec: {
  //       applyTo: [{ groups: [""], versions: ["v1"], kinds: ["Pod"] }],
  //       match: { scope: "Namespaced", kinds: [{ apiGroups: ["*"], kinds: ["Pod"] }] },
  //       location: "spec.containers[name:*].securityContext.capabilities.add",
  //       parameters: {
  //         values: {
  //           fromList: PSP.spec?.defaultAddCapabilities || []
  //         }
  //       }
  //     }
  //   })
  // if (PSP.spec?.defaultAllowPrivilegeEscalation !== undefined) {
  //   policies.push({
  //     apiVersion: "mutations.gatekeeper.sh/v1beta1",
  //     kind: "ModifySet",
  //     metadata: { name: "psp-k8spspdefaultallowprivilegeescalation" },
  //     spec: {
  //       applyTo: [{ groups: [""], versions: ["v1"], kinds: ["Pod"] }],
  //       location: "spec.containers[name:*].securityContext.allowPrivilegeEscalation",
  //       parameters: {
  //         pathTests: [{
  //           subPath: "spec.containers[name:*].securityContext.allowPrivilegeEscalation",
  //           condition: "MustNotExist"
  //         }],
  //         assign: { value: PSP.spec?.defaultAllowPrivilegeEscalation }
  //       }
  //     }
  //   })
  //   policies.push({
  //     apiVersion: "mutations.gatekeeper.sh/v1beta1",
  //     kind: "ModifySet",
  //     metadata: { name: "psp-k8spspdefaultallowprivilegeescalation-init" },
  //     spec: {
  //       applyTo: [{ groups: [""], versions: ["v1"], kinds: ["Pod"] }],
  //       location: "spec.initContainers[name:*].securityContext.allowPrivilegeEscalation",
  //       parameters: {
  //         pathTests: [{
  //           subPath: "spec.initContainers[name:*].securityContext.allowPrivilegeEscalation",
  //           condition: "MustNotExist"
  //         }],
  //         assign: { value: PSP.spec?.defaultAllowPrivilegeEscalation }
  //       }
  //     }
  //   })
  // }
  return policies
}
