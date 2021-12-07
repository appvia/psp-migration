import * as k8s from '@kubernetes/client-node'
import * as yaml from 'js-yaml'
import { createHash } from 'crypto'

import * as mod from './index'
export function parse(string: string): k8s.V1beta1PodSecurityPolicy {
  return yaml.load(string) as k8s.V1beta1PodSecurityPolicy
}


export function transform(PSP: k8s.V1beta1PodSecurityPolicy, engine: string): object[] {
  //@ts-ignore
  return mod[`transform_${engine}`](PSP).map(mod.unique_names)
}

export function transform_gatekeeper(PSP: k8s.V1beta1PodSecurityPolicy): object[] {
  const policies = []
  if (PSP.spec?.allowPrivilegeEscalation === false)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowPrivilegeEscalationContainer'))

  if (PSP.spec?.privileged === false)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPPrivilegedContainer'))

  if (PSP.spec?.readOnlyRootFilesystem === true)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPReadOnlyRootFilesystem'))

  if (PSP.spec?.hostIPC === true || PSP.spec?.hostPID === true)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostNamespace'))

  if (PSP.spec?.hostPorts)
    PSP.spec?.hostPorts.forEach(portRange =>
      policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostNetworkingPorts', { hostNetwork: true, min: portRange.min, max: portRange.max }))
    )
  else if (PSP.spec?.hostNetwork === false)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostNetworkingPorts', { hostNetwork: true }))

  if (!PSP.spec?.volumes?.includes('*'))
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPVolumeTypes', { volumes: PSP.spec?.volumes }))

  if (PSP.metadata?.annotations && PSP.metadata?.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'])
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAppArmor', { allowedProfiles: PSP.metadata?.annotations['apparmor.security.beta.kubernetes.io/allowedProfileNames'].split(',') }))

  if (PSP.metadata?.annotations && PSP.metadata?.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'])
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPSeccomp', { allowedProfiles: PSP.metadata?.annotations['seccomp.security.alpha.kubernetes.io/allowedProfileNames'].split(',') }))

  if (PSP.spec?.seLinux?.rule === 'MustRunAs')
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPSELinuxV2', { allowedSELinuxOptions: [PSP.spec?.seLinux?.seLinuxOptions] }))

  if (PSP.spec?.allowedCapabilities || PSP.spec?.requiredDropCapabilities)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPCapabilities', { allowedCapabilities: (PSP.spec?.allowedCapabilities || []), requiredDropCapabilities: (PSP.spec?.requiredDropCapabilities || []) }))

  if (PSP.spec?.allowedFlexVolumes)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPFlexVolumes', { allowedFlexVolumes: PSP.spec?.allowedFlexVolumes }))

  if (PSP.spec?.allowedHostPaths)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostFilesystem', { allowedHostPaths: PSP.spec?.allowedHostPaths }))

  if (PSP.spec?.allowedProcMountTypes)
    PSP.spec?.allowedProcMountTypes.forEach(procMountType =>
      policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPProcMount', { procMount: procMountType })))

  if (PSP.spec?.allowedHostPaths)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPHostFilesystem', { allowedHostPaths: PSP.spec?.allowedHostPaths }))

  if (PSP.spec?.allowedUnsafeSysctls || PSP.spec?.forbiddenSysctls)
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPForbiddenSysctls', { allowedSysctls: (PSP.spec?.allowedUnsafeSysctls || []), forbiddenSysctls: (PSP.spec?.forbiddenSysctls || []) }))

  if (PSP.spec?.runAsUser && PSP.spec?.runAsUser?.rule !== 'RunAsAny')
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { runAsUser: PSP.spec?.runAsUser }))

  if (PSP.spec?.runAsGroup && PSP.spec?.runAsGroup?.rule !== 'RunAsAny')
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { runAsGroup: PSP.spec?.runAsGroup }))

  if (PSP.spec?.supplementalGroups && PSP.spec?.supplementalGroups?.rule !== 'RunAsAny')
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { supplementalGroups: PSP.spec?.supplementalGroups }))

  if (PSP.spec?.fsGroup && PSP.spec?.fsGroup?.rule !== 'RunAsAny')
    policies.push(mod.gatekeeper_pod_policy_helper('K8sPSPAllowedUsers', { fsGroup: PSP.spec?.fsGroup }))

  if (PSP.spec?.defaultAddCapabilities)
    policies.push({
      apiVersion: "mutations.gatekeeper.sh/v1beta1",
      kind: "ModifySet",
      metadata: { name: "psp-k8spspdefaultaddcapabilities" },
      spec: {
        applyTo: [{ groups: [""], versions: ["v1"], kinds: ["Pod"] }],
        match: { scope: "Namespaced", kinds: [{ apiGroups: ["*"], kinds: ["Pod"] }] },
        location: "spec.containers[name:*].securityContext.capabilities.add",
        parameters: {
          values: {
            fromList: PSP.spec?.defaultAddCapabilities || []
          }
        }
      }
    })
  if (PSP.spec?.defaultAllowPrivilegeEscalation !== undefined) {
    policies.push({
      apiVersion: "mutations.gatekeeper.sh/v1beta1",
      kind: "ModifySet",
      metadata: { name: "psp-k8spspdefaultallowprivilegeescalation" },
      spec: {
        applyTo: [{ groups: [""], versions: ["v1"], kinds: ["Pod"] }],
        location: "spec.containers[name:*].securityContext.allowPrivilegeEscalation",
        parameters: {
          pathTests: [{
            subPath: "spec.containers[name:*].securityContext.allowPrivilegeEscalation",
            condition: "MustNotExist"
          }],
          assign: { value: PSP.spec?.defaultAllowPrivilegeEscalation }
        }
      }
    })
    policies.push({
      apiVersion: "mutations.gatekeeper.sh/v1beta1",
      kind: "ModifySet",
      metadata: { name: "psp-k8spspdefaultallowprivilegeescalation-init" },
      spec: {
        applyTo: [{ groups: [""], versions: ["v1"], kinds: ["Pod"] }],
        location: "spec.initContainers[name:*].securityContext.allowPrivilegeEscalation",
        parameters: {
          pathTests: [{
            subPath: "spec.initContainers[name:*].securityContext.allowPrivilegeEscalation",
            condition: "MustNotExist"
          }],
          assign: { value: PSP.spec?.defaultAllowPrivilegeEscalation }
        }
      }
    })
  }
  return policies
}


export function gatekeeper_pod_policy_helper(kind: string, parameters: object | null = null): object {
  return {
    apiVersion: "constraints.gatekeeper.sh/v1beta1",
    kind: kind,
    metadata: {
      name: `psp-${kind.toLowerCase()}`,
    },
    spec: {
      match: {
        kinds: [
          {
            apiGroups: [""],
            kinds: ["Pod"]
          }
        ]
      },
      parameters: parameters
    }
  }
}

export function unique_names(obj: object): object {
  const hash = createHash('sha256').update(JSON.stringify(obj)).digest('hex').substring(0, 5).toLowerCase()
  //@ts-ignore
  obj.metadata.name = `${obj.metadata.name}-${hash}`
  return obj
}