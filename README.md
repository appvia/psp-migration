# Kubernetes [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) Migration

> PodSecurityPolicy is dead, long live ???

[![CI](https://github.com/appvia/psp-migration/actions/workflows/ci.yml/badge.svg)](https://github.com/appvia/psp-migration/actions/workflows/ci.yml)
[![GitHub issues](https://img.shields.io/github/issues/appvia/psp-migration)](https://github.com/appvia/psp-migration/issues)
[![GitHub forks](https://img.shields.io/github/forks/appvia/psp-migration)](https://github.com/appvia/psp-migration/network)
[![GitHub stars](https://img.shields.io/github/stars/appvia/psp-migration)](https://github.com/appvia/psp-migration/stargazers)
![GitHub contributors](https://img.shields.io/github/contributors/appvia/psp-migration)
![GitHub last commit](https://img.shields.io/github/last-commit/appvia/psp-migration)
[![Appvia Community Slack](https://img.shields.io/badge/slack-@appvia_community-default.svg?logo=slack)](https://join.slack.com/t/appvia-community/shared_invite/zt-rcqz9vif-eDDQrbD_EAZBxsem30c2bQ)
[![GitHub license](https://img.shields.io/github/license/appvia/psp-migration)](https://github.com/appvia/psp-migration/blob/main/LICENSE)

# Please see our blog post [PodSecurityPolicy is Dead, Long Live...?](https://www.appvia.io/blog/podsecuritypolicy-is-dead-long-live)!
---

## 🚨 🚧 UNDER ACTIVE DEVELOPMENT (pull requests welcome) 🚧 🚨

This project is striving to recreate common Pod Security Policy configuration in other common kubernetes policy engines, to better inform the consumer how to migrate before it is removed in Kubernetes 1.25


## Installation

Download the right binary for your OS and Arch from the [latest release](https://github.com/appvia/psp-migration/releases/latest)

Or you can **[try it now in your browser](https://appvia.github.io/psp-migration/)!**

## Usage

The app takes PodSecurityPolicy on `stdIn` and output your policy engine of choice on `stdOut`, you select the policy engine with the `--engine=<engine>`:

```bash
$ cat psp.yaml | ./psp-migration --engine=gatekeeper > output.yaml
# or if you're feeling brave you can pipe it back and forth to the kubernetes api
$ kubectl get -o yaml mypodsecuritypolicy | ./psp-migration -e kubewarden | kubectl apply -f -
```

## Known limitations

- Generated policy will probably be pretty verbose
- Generated policy will probably have some unintended side effects, please [create an issue](https://github.com/appvia/psp-migration/issues/new?assignees=&labels=bug%2Ctriage&template=bug.yaml&title=%5BBug%5D%3A+) when this happens
- Only takes one PodSecurityPolicy at a time
- Generated policy may conflict with other policies

## Features

### :warning: This table is manually updated, see the [automated test suites results](https://github.com/appvia/psp-migration/actions/workflows/ci.yml) :warning:

> Note: ❌ Doesn't mean it doesn't work, it just means the test is currently failing, in most cases the test needs to be updated

| PSP field                                                                  | [Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) | [Pod Security Standard (baseline)](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | [Gatekeeper](https://github.com/open-policy-agent/gatekeeper) | [Kyverno](https://github.com/kyverno/kyverno)             | [Kubewarden](https://github.com/kubewarden/kubewarden-controller) | [k-rail](https://github.com/cruise-automation/k-rail)   |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------- |
| [privileged](./tests/privileged)                                           | [✔️](./tests/privileged/psp.yaml)                                                       | [✔️](./tests/privileged/pss.yaml)                                                                       | [✔️](./tests/privileged/gatekeeper.yaml)                       | [✔️](./tests/privileged/kyverno.yaml)                      | [✔️](./tests/privileged/kubewarden.yaml)                           | [✔️](./tests/privileged/krail.yaml)                      |
| [hostPID](./tests/hostPID)                                                 | [✔️](./tests/hostPID/psp.yaml)                                                          | [✔️](./tests/hostPID/pss.yaml)                                                                          | [✔️](./tests/hostPID/hostPID.yaml)                             | [✔️](./tests/hostPID/kyverno.yaml)                         | [✔️](./tests/hostPID/kubewarden.yaml)                              | [✔️](./tests/hostPID/krail.yaml)                         |
| [hostIPC](./tests/hostIPC)                                                 | [✔️](./tests/hostIPC/psp.yaml)                                                          | [✔️](./tests/hostIPC/pss.yaml)                                                                          | [✔️](./tests/hostIPC/gatekeeper.yaml)                          | [✔️](./tests/hostIPC/kyverno.yaml)                         | [✔️](./tests/hostIPC/kubewarden.yaml)                              | [❌](./tests/hostIPC/krail.yaml)                         |
| [hostNetwork](./tests/hostNetwork)                                         | [✔️](./tests/hostNetwork/psp.yaml)                                                      | [✔️](./tests/hostNetwork/pss.yaml)                                                                      | [✔️](./tests/hostNetwork/gatekeeper.yaml)                      | [✔️](./tests/hostNetwork/kyverno.yaml)                     | [✔️](./tests/hostNetwork/kubewarden.yaml)                          | [✔️](./tests/hostNetwork/krail.yaml)                     |
| [hostPorts](./tests/hostPorts)                                             | [✔️](./tests/hostPorts/psp.yaml)                                                        | [❌](./tests/hostPorts/pss.yaml)                                                                        | [✔️](./tests/hostPorts/gatekeeper.yaml)                        | [✔️](./tests/hostPorts/kyverno.yaml)                       | [✔️](./tests/hostPorts/kubewarden.yaml)                            | [❌](./tests/hostPorts/krail.yaml)                       |
| [volumes](./tests/volumes)                                                 | [✔️](./tests/volumes/psp.yaml)                                                          | [✔️](./tests/volumes/pss.yaml)                                                                          | [✔️](./tests/volumes/gatekeeper.yaml)                          | [✔️](./tests/volumes/kyverno.yaml)                         | [✔️](./tests/volumes/kubewarden.yaml)                              | [❌](./tests/volumes/krail.yaml)                         |
| [allowedHostPaths](./tests/allowedHostPaths)                               | [✔️](./tests/allowedHostPaths/psp.yaml)                                                 | [❌](./tests/allowedHostPaths/pss.yaml)                                                                 | [✔️](./tests/allowedHostPaths/gatekeeper.yaml)                 | [✔️](./tests/allowedHostPaths/kyverno.yaml)                | [✔️](./tests/allowedHostPaths/kubewarden.yaml)                     | [❌](./tests/allowedHostPaths/krail.yaml)                |
| [allowedFlexVolumes](./tests/allowedFlexVolumes)                           | [✔️](./tests/allowedFlexVolumes/psp.yaml)                                               | [❌](./tests/allowedFlexVolumes/pss.yaml)                                                               | [✔️](./tests/allowedFlexVolumes/gatekeeper.yaml)               | [✔️](./tests/allowedFlexVolumes/kyverno.yaml)              | [✔️](./tests/allowedFlexVolumes/kubewarden.yaml)                   | [❌](./tests/allowedFlexVolumes/krail.yaml)              |
| [readOnlyRootFilesystem](./tests/readOnlyRootFilesystem)                   | [✔️](./tests/readOnlyRootFilesystem/psp.yaml)                                           | [❌](./tests/readOnlyRootFilesystem/pss.yaml)                                                           | [✔️](./tests/readOnlyRootFilesystem/gatekeeper.yaml)           | [✔️](./tests/readOnlyRootFilesystem/kyverno.yaml)          | [✔️](./tests/readOnlyRootFilesystem/kubewarden.yaml)               | [❌](./tests/readOnlyRootFilesystem/krail.yaml)          |
| [runAsUser](./tests/runAsUser)                                             | [✔️](./tests/runAsUser/psp.yaml)                                                        | [❌](./tests/runAsUser/pss.yaml)                                                                        | [✔️](./tests/runAsUser/gatekeeper.yaml)                        | [✔️](./tests/runAsUser/kyverno.yaml)                       | [✔️](./tests/runAsUser/kubewarden.yaml)                            | [❌](./tests/runAsUser/krail.yaml)                       |
| [runAsGroup](./tests/runAsGroup)                                           | [✔️](./tests/runAsGroup/psp.yaml)                                                       | [❌](./tests/runAsGroup/pss.yaml)                                                                       | [✔️](./tests/runAsGroup/gatekeeper.yaml)                       | [✔️](./tests/runAsGroup/kyverno.yaml)                      | [✔️](./tests/runAsGroup/kubewarden.yaml)                           | [❌](./tests/runAsGroup/krail.yaml)                      |
| [supplementalGroups](./tests/supplementalGroups)                           | [✔️](./tests/supplementalGroups/psp.yaml)                                               | [❌](./tests/supplementalGroups/pss.yaml)                                                               | [✔️](./tests/supplementalGroups/gatekeeper.yaml)               | [✔️](./tests/supplementalGroups/kyverno.yaml)              | [✔️](./tests/supplementalGroups/kubewarden.yaml)                   | [❌](./tests/supplementalGroups/krail.yaml)              |
| [fsgroup](./tests/fsgroup)                                                 | [✔️](./tests/fsgroup/psp.yaml)                                                          | [❌](./tests/fsgroup/pss.yaml)                                                                          | [✔️](./tests/fsgroup/gatekeeper.yaml)                          | [✔️](./tests/fsgroup/kyverno.yaml)                         | [✔️](./tests/fsgroup/kubewarden.yaml)                              | [❌](./tests/fsgroup/krail.yaml)                         |
| [allowPrivilegeEscalation](./tests/allowPrivilegeEscalation)               | [✔️](./tests/allowPrivilegeEscalation/psp.yaml)                                         | [❌](./tests/allowPrivilegeEscalation/pss.yaml)                                                         | [✔️](./tests/allowPrivilegeEscalation/gatekeeper.yaml)         | [✔️](./tests/allowPrivilegeEscalation/kyverno.yaml)        | [✔️](./tests/allowPrivilegeEscalation/kubewarden.yaml)             | [❌](./tests/allowPrivilegeEscalation/krail.yaml)        |
| [defaultAllowPrivilegeEscalation](./tests/defaultAllowPrivilegeEscalation) | [✔️](./tests/defaultAllowPrivilegeEscalation/psp.yaml)                                  | [❌](./tests/defaultAllowPrivilegeEscalation/pss.yaml)                                                  | [✔️](./tests/defaultAllowPrivilegeEscalation/gatekeeper.yaml)  | [✔️](./tests/defaultAllowPrivilegeEscalation/kyverno.yaml) | [✔️](./tests/defaultAllowPrivilegeEscalation/kubewarden.yaml)      | [❌](./tests/defaultAllowPrivilegeEscalation/krail.yaml) |
| [allowedCapabilities](./tests/allowedCapabilities)                         | [✔️](./tests/allowedCapabilities/psp.yaml)                                              | [❌](./tests/allowedCapabilities/pss.yaml)                                                              | [✔️](./tests/allowedCapabilities/gatekeeper.yaml)              | [✔️](./tests/allowedCapabilities/kyverno.yaml)             | [✔️](./tests/allowedCapabilities/kubewarden.yaml)                  | [❌](./tests/allowedCapabilities/krail.yaml)             |
| [defaultAddCapabilities](./tests/defaultAddCapabilities)                   | [✔️](./tests/defaultAddCapabilities/psp.yaml)                                           | [❌](./tests/defaultAddCapabilities/pss.yaml)                                                           | [✔️](./tests/defaultAddCapabilities/gatekeeper.yaml)           | [✔️](./tests/defaultAddCapabilities/kyverno.yaml)          | [✔️](./tests/defaultAddCapabilities/kubewarden.yaml)               | [❌](./tests/defaultAddCapabilities/krail.yaml)          |
| [requiredDropCapabilities](./tests/requiredDropCapabilities)               | [✔️](./tests/requiredDropCapabilities/psp.yaml)                                         | [❌](./tests/requiredDropCapabilities/pss.yaml)                                                         | [✔️](./tests/requiredDropCapabilities/gatekeeper.yaml)         | [✔️](./tests/requiredDropCapabilities/kyverno.yaml)        | [✔️](./tests/requiredDropCapabilities/kubewarden.yaml)             | [❌](./tests/requiredDropCapabilities/krail.yaml)        |
| [seLinux](./tests/seLinux)                                                 | [✔️](./tests/seLinux/psp.yaml)                                                          | [❌](./tests/seLinux/pss.yaml)                                                                          | [✔️](./tests/seLinux/gatekeeper.yaml)                          | [✔️](./tests/seLinux/kyverno.yaml)                         | [❌](./tests/seLinux/kubewarden.yaml)                              | [❌](./tests/seLinux/krail.yaml)                         |
| [allowedProcMountTypes](./tests/allowedProcMountTypes)                     | [✔️](./tests/allowedProcMountTypes/psp.yaml)                                            | [❌](./tests/allowedProcMountTypes/pss.yaml)                                                            | [✔️](./tests/allowedProcMountTypes/gatekeeper.yaml)            | [✔️](./tests/allowedProcMountTypes/kyverno.yaml)           | [✔️](./tests/allowedProcMountTypes/kubewarden.yaml)                | [❌](./tests/allowedProcMountTypes/krail.yaml)           |
| [apparmor](./tests/apparmor)                                               | [✔️](./tests/apparmor/psp.yaml)                                                         | [✔️](./tests/apparmor/pss.yaml)                                                                         | [✔️](./tests/apparmor/gatekeeper.yaml)                         | [✔️](./tests/apparmor/kyverno.yaml)                        | [✔️](./tests/apparmor/kubewarden.yaml)                             | [✔️](./tests/apparmor/krail.yaml)                        |
| [seccomp](./tests/seccomp)                                                 | [✔️](./tests/seccomp/psp.yaml)                                                          | [✔️](./tests/seccomp/pss.yaml)                                                                          | [✔️](./tests/seccomp/gatekeeper.yaml)                          | [✔️](./tests/seccomp/kyverno.yaml)                         | [✔️](./tests/seccomp/kubewarden.yaml)                              | [❌](./tests/seccomp/krail.yaml)                         |
| [forbiddenSysctls](./tests/forbiddenSysctls)                               | [✔️](./tests/forbiddenSysctls/psp.yaml)                                                 | [❌](./tests/forbiddenSysctls/pss.yaml)                                                                 | [✔️](./tests/forbiddenSysctls/gatekeeper.yaml)                 | [✔️](./tests/forbiddenSysctls/kyverno.yaml)                | [✔️](./tests/forbiddenSysctls/kubewarden.yaml)                     | [❌](./tests/forbiddenSysctls/krail.yaml)                |
| [allowedUnsafeSysctls](./tests/allowedUnsafeSysctls)                       | [✔️](./tests/allowedUnsafeSysctls/psp.yaml)                                             | [❌](./tests/allowedUnsafeSysctls/pss.yaml)                                                             | [✔️](./tests/allowedUnsafeSysctls/gatekeeper.yaml)             | [✔️](./tests/allowedUnsafeSysctls/kyverno.yaml)            | [✔️](./tests/allowedUnsafeSysctls/kubewarden.yaml)                 | [❌](./tests/allowedUnsafeSysctls/krail.yaml)            |

## References

- https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/
- https://github.com/open-policy-agent/gatekeeper-library
- https://kubernetes.io/docs/concepts/security/pod-security-standards/
- https://github.com/open-policy-agent/gatekeeper
- https://github.com/kyverno/kyverno
- https://github.com/kyverno/policies
- https://github.com/kubewarden/kubewarden-controller
- https://hub.kubewarden.io/
- https://github.com/cruise-automation/k-rail/blob/master/charts/k-rail/values.yaml
- https://github.com/cruise-automation/k-rail
