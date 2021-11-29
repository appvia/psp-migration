#!/usr/bin/env bats

setup() {
  local -r testcase="${BATS_TEST_NAME:5}"
  if [ -f tests/${testcase}/${SYSTEM}.yaml ]; then
    kubectl apply -f tests/${testcase}/${SYSTEM}.yaml
    if [ "${SYSTEM}" == "kyverno" ]; then
      while [[ $(kubectl get -f tests/${testcase}/${SYSTEM}.yaml -o 'jsonpath={..status.ready}') != "true" ]]; do sleep 1; done
    fi
    if [ "${SYSTEM}" == "kubewarden" ]; then
      kubectl wait --for=condition=PolicyActive --timeout=120s -f tests/${testcase}/${SYSTEM}.yaml
    fi
    if [ "${SYSTEM}" == "pss" ]; then
      kubectl config set-context --current --namespace=test
    fi
  fi
  kubectl apply -f tests/${testcase}/allowed.yaml 
  ! kubectl apply -f tests/${testcase}/disallowed.yaml 
}

teardown() {
  local -r testcase="${BATS_TEST_NAME:5}"
  kubectl delete -f tests/${testcase}/allowed.yaml 
  ! kubectl delete -f tests/${testcase}/disallowed.yaml
  if [ -f tests/${testcase}/${SYSTEM}.yaml ]; then
    kubectl delete --wait -f tests/${testcase}/${SYSTEM}.yaml
    if [ "${SYSTEM}" == "kyverno" ]; then
      while [[ $(kubectl get -f tests/${testcase}/${SYSTEM}.yaml -o 'jsonpath={..status.ready}') == "true" ]]; do sleep 1; done
    fi
    if [ "${SYSTEM}" == "pss" ]; then
      kubectl config set-context --current --namespace=default
    fi
  fi
}


@test "privileged" {}
@test "hostPID" {}
@test "hostIPC" {}
@test "hostNetwork" {} 
@test "hostPorts" {} # @TODO make kyverno policy
@test "volumes" {}
@test "allowedHostPaths" {} # @TODO make kyverno policy
@test "allowedFlexVolumes" {} # @TODO make kyverno policy
@test "readOnlyRootFilesystem" {} # @TODO make kyverno policy
@test "runAsUser" {} # @TODO make kyverno policy
@test "runAsGroup" {} # @TODO make kyverno policy
@test "supplementalGroups" {} # @TODO make kyverno policy
@test "fsgroup" {} # @TODO make kyverno policy
@test "allowPrivilegeEscalation" {}
@test "defaultAllowPrivilegeEscalation" {}  # @TODO make kyverno policy
@test "allowedCapabilities" {}
@test "defaultAddCapabilities" {} # @TODO gatekeeper mutator overrides the defined capabilities
@test "requiredDropCapabilities" {}  # @TODO make kyverno policy
@test "seLinux" {} # @TODO make kyverno policy
@test "allowedProcMountTypes" {}
@test "apparmor" {}
@test "seccomp" {}
@test "forbiddenSysctls" {} # @TODO make kyverno policy
@test "allowedUnsafeSysctls" {} # @TODO make kyverno policy