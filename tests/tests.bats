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
  kubectl delete --wait=false -f tests/${testcase}/${SYSTEM}.yaml
  kubectl delete --wait=false -f tests/${testcase}/allowed.yaml 
  ! kubectl delete --wait=false -f tests/${testcase}/disallowed.yaml
}


@test "privileged" {}
@test "hostPID" {}
@test "hostIPC" {}
@test "hostNetwork" {}
@test "hostPorts" {}
@test "volumes" {}
@test "allowedHostPaths" {}
@test "allowedFlexVolumes" {}
@test "readOnlyRootFilesystem" {}