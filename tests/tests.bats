#!/usr/bin/env bats

setup() {
  local -r testcase="${BATS_TEST_NAME:5}"
  kubectl apply -f tests/${testcase}/${SYSTEM}.yaml
  # if [ "${SYSTEM}" == "gatekeeper"]; then
    # sleep 5 # @TODO replace with wait
  # fi
  kubectl apply -f tests/${testcase}/allowed.yaml 
  ! kubectl apply -f tests/${testcase}/disallowed.yaml 
}

teardown() {
  local -r testcase="${BATS_TEST_NAME:5}"
  kubectl delete -f tests/${testcase}/${SYSTEM}.yaml
  kubectl delete -f tests/${testcase}/allowed.yaml 
  ! kubectl delete -f tests/${testcase}/disallowed.yaml
}


@test "privileged" {}
@test "hostPID" {}
@test "hostIPC" {}
@test "hostNetwork" {} # @TODO in gatekeeper, not implemented with library
@test "hostPorts" {}
@test "volumes" {}
@test "allowedHostPaths" {}
@test "allowedFlexVolumes" {}
@test "readOnlyRootFilesystem" {}
@test "runAsUser" {}
@test "runAsGroup" {}
@test "supplementalGroups" {}
@test "fsgroup" {}
@test "allowPrivilegeEscalation" {}
@test "defaultAllowPrivilegeEscalation" {}
@test "allowedCapabilities" {}
@test "defaultAddCapabilities" {} # @TODO in gatekeeper, not implemented with library
@test "requiredDropCapabilities" {}
@test "seLinux" {}
@test "allowedProcMountTypes" {} # @TODO This requires the ProcMountType feature flag to be enabled. Set --feature-gates=ProcMountType=true
@test "apparmor" {}
@test "seccomp" {}
@test "forbiddenSysctls" {}
@test "allowedUnsafeSysctls" {} # @TODO By default, all safe sysctls are allowed. If you wish to use unsafe sysctls, make sure to whitelist --allowed-unsafe-sysctls kubelet flag on each node. For example, --allowed-unsafe-sysctls='kernel.msg*,kernel.shm.*,net.*'.