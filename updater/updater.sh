#!/bin/bash

get_latest_tag() {
    local image=$(echo $1 | sed -E 's/(.*):.*/\1/')
    local tags=$(skopeo list-tags --tls-verify=false docker://$image)
    local latest_tag=$(echo $tags | jq -r '[.Tags[] | select(.!="latest")][-1]')
    echo $image:$latest_tag
}

replace_files_with_latest_tag() {
  local before=$1
  local after=$(get_latest_tag ${before})
  local files=$(find . -type f -exec grep -l ${before} {} \; )

  echo replacing ${before} with ${after} in $files
  echo "$files" | xargs -I@ sed "s|${before}|${after}|g" @ -i 
}

IMAGES=(
    ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.1.10
    ghcr.io/kubewarden/policies/capabilities-psp:v0.1.8
    ghcr.io/kubewarden/policies/flexvolume-drivers-psp:v0.1.1
    ghcr.io/kubewarden/policies/hostpaths-psp:v0.1.4
    ghcr.io/kubewarden/policies/allowed-proc-mount-types-psp:v0.1.1
    ghcr.io/kubewarden/policies/sysctl-psp:v0.1.6
    ghcr.io/kubewarden/policies/apparmor-psp:v0.1.8
    ghcr.io/kubewarden/policies/capabilities-psp:v0.1.8
    ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.1.10
    ghcr.io/kubewarden/policies/sysctl-psp:v0.1.6
    ghcr.io/kubewarden/policies/allowed-fsgroups-psp:v0.1.1
    ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.1
    ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.1
    ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.1
    ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.1
    ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
    ghcr.io/kubewarden/policies/readonly-root-filesystem-psp:v0.1.2
    ghcr.io/kubewarden/policies/capabilities-psp:v0.1.8
    ghcr.io/kubewarden/policies/user-group-psp:v0.1.4
    ghcr.io/kubewarden/policies/user-group-psp:v0.1.4
    ghcr.io/kubewarden/policies/selinux-psp:v0.1.2
    ghcr.io/jvanz/policies/seccomp-psp:issue6
    ghcr.io/kubewarden/policies/user-group-psp:v0.1.4
)

for IMAGE in "${IMAGES[@]}"
do
  replace_files_with_latest_tag "${IMAGE}"
done