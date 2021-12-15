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
    rule.match = { resources: { kinds: ["Pod"] } }
    rule.name = `${this.metadata?.name}-${this.spec.rules.length}`
    if (rule.validate)
      rule.validate.message = `Rejected by ${rule.name} rule`
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

  if (PSP.metadata?.annotations && PSP.metadata?.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames']) {
    let policy = new ClusterPolicy('apparmor')
    policy.addRule({ validate: { pattern: { metadata: { "=(annotations)": { "=(container.apparmor.security.beta.kubernetes.io/*)": PSP.metadata?.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'] } } } } })
    policies.push(policy)
  }

  if (PSP.metadata?.annotations && PSP.metadata?.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames']) {
    let policy = new ClusterPolicy('seccomp')
    policy.addRule({ validate: { pattern: { metadata: { "=(annotations)": { "=(container.apparmor.security.beta.kubernetes.io/*)": PSP.metadata?.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'] } } } } })
    policies.push(policy)
  }

  if (PSP.spec?.seLinux?.rule === 'MustRunAs') {
    let policy = new ClusterPolicy('seLinux')
    let seLinuxOptions = PSP.spec?.seLinux?.seLinuxOptions
    policy.addRule({
      validate: {
        anyPattern: [
          {
            spec: { securityContext: { seLinuxOptions } }
          },
          {
            spec: {
              "=(securityContext)": { "=(seLinuxOptions)": seLinuxOptions },
              containers: [{ securityContext: { seLinuxOptions } }],
              "=(initContainers)": [{ securityContext: { seLinuxOptions } }]
            }
          }
        ]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.allowedCapabilities) {
    let policy = new ClusterPolicy('allowedCapabilities')
    let deny = { conditions: { any: [{ key: "{{ element.add }}", operator: "AnyNotIn", value: PSP.spec?.allowedCapabilities }] } }
    policy.addRule({
      preconditions: {
        all: [{
          key: "{{ request.object.spec.initContainers[] | length(@) }}",
          operator: "GreaterThanOrEquals",
          value: 1
        }]
      },
      validate: { foreach: [{ list: "request.object.spec.initContainers[].securityContext.capabilities", deny }] }
    })
    policy.addRule({
      validate: { foreach: [{ list: "request.object.spec.containers[].securityContext.capabilities", deny }] }
    })
    policies.push(policy)
  }

  if (PSP.spec?.requiredDropCapabilities) {
    let policy = new ClusterPolicy('requiredDropCapabilities')
    let securityContext = { securityContext: { capabilities: { drop: PSP.spec?.requiredDropCapabilities } } }
    policy.addRule(wrap_validate_spec({ containers: [securityContext], "=(ephemeralContainers)": [securityContext], "=(initContainers)": [securityContext] }))
    policies.push(policy)
  }


  if (PSP.spec?.allowedFlexVolumes) {
    //@TODO doesn't support multiple allowedFlexVolumes
    let policy = new ClusterPolicy('allowedFlexVolumes')
    policy.addRule(wrap_validate_spec({ "=(volumes)": [{ "=(flexVolume)": { driver: PSP.spec?.allowedFlexVolumes[0] } }] }))
    policies.push(policy)
  }


  if (PSP.spec?.allowedHostPaths) {
    //@TODO doesn't support multiple allowedHostPaths
    let policy = new ClusterPolicy('allowedHostPaths')
    policy.addRule({
      preconditions: { all: [{ key: "{{ request.object.spec.volumes[?hostPath] | length(@) }}", operator: "GreaterThanOrEquals", value: 1 }] },
      validate: { foreach: [{ list: "request.object.spec.volumes[?hostPath].hostPath", deny: { conditions: [{ key: "{{ element.path  | to_string(@) | split(@, '/') | [1] }}", operator: "NotEquals", value: PSP.spec?.allowedHostPaths[0].pathPrefix }] } }] }
    })
    policies.push(policy)
  }

  if (PSP.spec?.allowedProcMountTypes) {
    //@TODO doesn't support multiple allowedProcMountTypes
    let policy = new ClusterPolicy('allowedProcMountTypes')
    let pol = [{ "=(securityContext)": { "=(procMount)": PSP.spec?.allowedProcMountTypes[0] } }]
    policy.addRule(wrap_validate_spec({ "=(initContainers)": pol, "=(ephemeralContainers)": pol, containers: pol }))
    policies.push(policy)
  }

  if (PSP.spec?.allowedUnsafeSysctls) {
    //@TODO doesn't support multiple allowedUnsafeSysctls or wildcards
    let policy = new ClusterPolicy('allowedUnsafeSysctls')
    let securitycontext = { "=(securityContext)": { "=(sysctls)": [{ name: PSP.spec?.allowedUnsafeSysctls[0] }] } }
    policy.addRule({
      validate: {
        anyPattern: [
          { spec: securitycontext },
          { spec: { containers: [securitycontext] } },
        ]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.forbiddenSysctls) {
    //@TODO doesn't support multiple forbiddenSysctls
    let policy = new ClusterPolicy('forbiddenSysctls')
    let securitycontext = { "=(securityContext)": { "=(sysctls)": [{ name: `!${PSP.spec?.forbiddenSysctls[0]}` }] } }
    policy.addRule({
      validate: {
        anyPattern: [
          { spec: securitycontext },
          { spec: { containers: [securitycontext] } },
        ]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.runAsUser && PSP.spec?.runAsUser?.rule !== 'RunAsAny') {
    // @TODO doesn't support multiple runAsUser
    let policy = new ClusterPolicy('runAsUser')
    let securityContext = { securityContext: { runAsUser: `>=${PSP.spec.runAsUser.ranges![0]!.min} <=${PSP.spec.runAsUser.ranges![0]!.max}` } }
    policy.addRule({
      validate: {
        anyPattern: [
          { spec: securityContext },
          {
            spec: {
              "=(securityContext)": { "=(runAsUser)": securityContext.securityContext.runAsUser },
              containers: [securityContext],
              "=(initContainers)": [securityContext],
              "=(ephemeralContainers)": [securityContext],
            }
          },
        ]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.runAsGroup && PSP.spec?.runAsGroup?.rule !== 'RunAsAny') {
    // @TODO doesn't support multiple runAsGroup
    let policy = new ClusterPolicy('runAsGroup')
    let securityContext = { securityContext: { runAsGroup: `>=${PSP.spec.runAsGroup.ranges![0]!.min} <=${PSP.spec?.runAsGroup?.ranges![0]!.max}` } }
    policy.addRule({
      validate: {
        anyPattern: [
          { spec: securityContext },
          {
            spec: {
              "=(securityContext)": { "=(runAsGroup)": securityContext.securityContext.runAsGroup },
              containers: [securityContext],
              "=(initContainers)": [securityContext],
              "=(ephemeralContainers)": [securityContext],
            }
          },
        ]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.fsGroup && PSP.spec?.fsGroup?.rule !== 'RunAsAny') {
    // @TODO doesn't support multiple fsGroup
    let policy = new ClusterPolicy('fsGroup')
    let securityContext = { securityContext: { fsGroup: `>=${PSP.spec?.fsGroup?.ranges![0]!.min} <=${PSP.spec?.fsGroup?.ranges![0]!.max}` } }
    policy.addRule({
      validate: {
        anyPattern: [
          { spec: securityContext },
          {
            spec: {
              "=(securityContext)": { "=(fsGroup)": securityContext.securityContext.fsGroup },
              containers: [securityContext],
              "=(initContainers)": [securityContext],
              "=(ephemeralContainers)": [securityContext],
            }
          },
        ]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.supplementalGroups && PSP.spec?.supplementalGroups?.rule !== 'RunAsAny') {
    let policy = new ClusterPolicy('supplementalGroups')
    let ranges = PSP.spec?.supplementalGroups?.ranges?.map(range => Array.from({ length: range.max - range.min + 1 }, (v, k) => k + range.min)).flat()
    policy.addRule({
      validate: {
        foreach: [{
          list: "request.object.spec.securityContext", deny: {
            conditions: {
              any: [{
                key: "{{ element.supplementalGroups }}",
                operator: "AnyNotIn",
                value: ranges
              }]
            }
          }
        }]
      }
    })
    policies.push(policy)
  }

  if (PSP.spec?.defaultAddCapabilities) {
    // @TODO doesn't support init or ephemeral containers
    let policy = new ClusterPolicy('defaultAddCapabilities')
    PSP.spec?.defaultAddCapabilities.forEach(capability =>
      policy.addRule({
        mutate: {
          patchesJson6902: `
- op: add
  path: "/spec/securityContext/capabilities/add/-"
  value: ${capability}`
        }
      })
    )
    policies.push(policy)
  }

  if (PSP.spec?.defaultAllowPrivilegeEscalation !== undefined) {
    // @TODO doesn't support init or ephemeral containers
    let policy = new ClusterPolicy('defaultAllowPrivilegeEscalation')
    policy.addRule({
      mutate: {
        patchesJson6902: `
- op: add
  path: "/spec/securityContext/allowPrivilegeEscalation"
  value: ${PSP.spec?.defaultAllowPrivilegeEscalation}`
      }
    })
    policies.push(policy)
  }
  return policies
}
