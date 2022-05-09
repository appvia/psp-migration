#!/usr/bin/env bats

setup() {
  local -r testcase="${BATS_TEST_NAME:5}"
  
  if  [ "${E2E_TEST:-false}" != 'false' ] ; then
    ${E2E_TEST} --engine=${SYSTEM} < tests/${testcase}/psp.yaml > tests/${testcase}/${SYSTEM}.yaml
  fi
  if [ -f tests/${testcase}/${SYSTEM}.yaml ]; then
    kubectl apply -f tests/${testcase}/${SYSTEM}.yaml
    if [ -f tests/${testcase}/${SYSTEM}-helper.yaml ]; then
      kubectl apply -f tests/${testcase}/${SYSTEM}-helper.yaml
    fi

    if [ "${SYSTEM}" == "kyverno" ]; then
      while [[ $(kubectl get -f tests/${testcase}/${SYSTEM}.yaml -o 'jsonpath={..status.ready}') != "true" ]]; do sleep 1; done
    fi
    if [ "${SYSTEM}" == "kubewarden" ]; then
      kubectl wait --for=condition=PolicyActive --timeout=60s -f tests/${testcase}/${SYSTEM}.yaml
    fi
    if [ "${SYSTEM}" == "pss" ]; then
      kubectl config set-context --current --namespace=test
    fi
    if [ "${SYSTEM}" == "krail" ]; then
      kubectl -n k-rail rollout restart deployment k-rail
      kubectl -n k-rail rollout status deployment k-rail
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
    if [ -f tests/${testcase}/${SYSTEM}-helper.yaml ]; then
      kubectl delete -f tests/${testcase}/${SYSTEM}-helper.yaml
    fi
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
@test "defaultAddCapabilities" {} 
@test "requiredDropCapabilities" {}  
@test "seLinux" {} 
@test "allowedProcMountTypes" {}
@test "apparmor" {}
@test "seccomp" {}
@test "forbiddenSysctls" {} 
@test "allowedUnsafeSysctls" {} 