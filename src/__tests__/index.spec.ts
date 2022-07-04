import * as mod from '../index'
import * as gatekeeper from '../gatekeeper'
import * as kyverno from '../kyverno'
import * as kubewarden from '../kubewarden'
import * as fs from 'fs'

const fixturePSPYAML = `
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: policy
spec:
  runAsUser:
    rule: RunAsAny
  seLinux:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  supplementalGroups:
    rule: 'RunAsAny'
  volumes:
    - '*'
`
const fixturePSPJSON = `{ "apiVersion": "policy/v1beta1", "kind": "PodSecurityPolicy", "metadata": { "name": "policy" }, "spec": { "runAsUser": { "rule": "RunAsAny" }, "seLinux": { "rule": "RunAsAny" }, "fsGroup": { "rule": "RunAsAny" }, "supplementalGroups": { "rule": "RunAsAny" }, "volumes": ["*"] } }`
const fixturePSPObject = { "apiVersion": "policy/v1beta1", "kind": "PodSecurityPolicy", "metadata": { "name": "policy" }, "spec": { "runAsUser": { "rule": "RunAsAny" }, "seLinux": { "rule": "RunAsAny" }, "fsGroup": { "rule": "RunAsAny" }, "supplementalGroups": { "rule": "RunAsAny" }, "volumes": ["*"] } }
const defaultKubewardenPolicies = [{"apiVersion": "policies.kubewarden.io/v1", "kind": "ClusterAdmissionPolicy", "metadata": { "name": "psp-privileged" }, "spec": { "module": "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.10", "mutating": false, "rules": [ { "apiGroups": [""], "apiVersions": [ "v1" ], "operations": ["CREATE", "UPDATE"],"resources": ["pods"]}],"settings": null}}, { "apiVersion": "policies.kubewarden.io/v1", "kind": "ClusterAdmissionPolicy", "metadata": { "name": "psp-hostnamespaces"}, "spec": { "module": "registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.2", "mutating": false, "rules": [ { "apiGroups": [""], "apiVersions": [ "v1"], "operations": [ "CREATE", "UPDATE"], "resources": [ "pods"]}], "settings": { "allow_host_ipc": false, "allow_host_network": false, "allow_host_pid": false, "allow_host_ports": undefined }}}]


describe('parse', () => {

  it('should parse a yaml object', () => expect(mod.parse(fixturePSPYAML)).toMatchSnapshot())

  it('should parse a json object', () => expect(mod.parse(fixturePSPJSON)).toMatchSnapshot())
})

describe('transform', () => {
  it('should call the right engine', () => {
    const spy = jest.spyOn(gatekeeper, "transform_gatekeeper")
    mod.transform(fixturePSPObject, 'gatekeeper')
    expect(spy).toHaveBeenCalled()
  })
})

function help_load_psp(fixture: string) {
  const yaml = fs.readFileSync(`tests/${fixture}/psp.yaml`, { flag: 'r' })
  return mod.parse(yaml.toString())
}

const pspFields = [
  "allowPrivilegeEscalation",
  "allowedCapabilities",
  "allowedFlexVolumes",
  "allowedHostPaths",
  "allowedProcMountTypes",
  "allowedUnsafeSysctls",
  "apparmor",
  "defaultAddCapabilities",
  "defaultAllowPrivilegeEscalation",
  "forbiddenSysctls",
  "fsgroup",
  "hostIPC",
  "hostNetwork",
  "hostPID",
  "hostPorts",
  "privileged",
  "readOnlyRootFilesystem",
  "requiredDropCapabilities",
  "runAsGroup",
  "runAsUser",
  "seLinux",
  "seccomp",
  "supplementalGroups",
  "volumes"
].map(field => [field])

describe('transform_gatekeeper', () => {
  it('should do an empty PSP', () => expect(gatekeeper.transform_gatekeeper(fixturePSPObject)).toStrictEqual([]))
  test.each(pspFields)('%s', (field) =>
    expect(gatekeeper.transform_gatekeeper(help_load_psp(field))).toMatchSnapshot()
  )
})

describe('transform_kyverno', () => {
  it('should do an empty PSP', () => expect(kyverno.transform_kyverno(fixturePSPObject)).toStrictEqual([]))
  test.each(pspFields)('%s', (field) =>
    expect(kyverno.transform_kyverno(help_load_psp(field))).toMatchSnapshot()
  )
})

describe('transform_kubewarden', () => {
  it('should have some default policies', () => expect(kubewarden.transform_kubewarden(fixturePSPObject)).toStrictEqual(defaultKubewardenPolicies))
  test.each(pspFields)('%s', (field) =>
    expect(kubewarden.transform_kubewarden(help_load_psp(field))).toMatchSnapshot()
  )
})
