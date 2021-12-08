import * as mod from '../index'
import * as gatekeeper from '../gatekeeper'
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