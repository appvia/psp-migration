// jest.mock('../src/github')
import * as mod from '../index'

// let processExitSpy
// let consoleSpy


describe('parse', () => {

  it('should parse a yaml object', () => {
    const yaml = `
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
        rule: MustRunAs
        ranges:
          - min: 100
            max: 200
      supplementalGroups:
        rule: 'RunAsAny'
      volumes:
        - '*'
    `
    return expect(mod.parse(yaml)).toMatchSnapshot()
  })

  it('should parse a json object', () => {
    const json = `{ "apiVersion": "policy/v1beta1", "kind": "PodSecurityPolicy", "metadata": { "name": "policy" }, "spec": { "runAsUser": { "rule": "RunAsAny" }, "seLinux": { "rule": "RunAsAny" }, "fsGroup": { "rule": "MustRunAs", "ranges": [{ "min": 100, "max": 200 }] }, "supplementalGroups": { "rule": "RunAsAny" }, "volumes": ["*"] } }`
    return expect(mod.parse(json)).toMatchSnapshot()
  })
})