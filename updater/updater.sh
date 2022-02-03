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
    ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:sha256-527c74ad60fb86a15c6d16acccddab6864f98d5a4cd62e5a8bde9548b5012083.sig
    ghcr.io/kubewarden/policies/capabilities-psp:sha256-55ee09e26c3b5240da51707b328e19db6b00a42eea46aee47a63f274b7cbc89c.sig
    ghcr.io/kubewarden/policies/flexvolume-drivers-psp:sha256-b2e44ce617f80a335f12341651d66a200611b5bbe392694e01212a69663a79f1.sig
    ghcr.io/kubewarden/policies/hostpaths-psp:sha256-b4633472498934a094c43f06ccf2e7cbc21f1fe573fc88485781b2e27e1b0a99.sig
    ghcr.io/kubewarden/policies/allowed-proc-mount-types-psp:sha256-9433dce568e969566a8b3bf842b9e0c39bbb99e8446e062421b748095a794c98.sig
    ghcr.io/kubewarden/policies/sysctl-psp:sha256-300d9e5cb09f475003b27c7df573864b85101e48f62befcaf385f9e44c939986.sig
    ghcr.io/kubewarden/policies/apparmor-psp:sha256-5d5895a39a3a4c3821c96b281da0296e3c664f3e90a3d4a0068486fcbf1d556b.sig
    ghcr.io/kubewarden/policies/capabilities-psp:sha256-55ee09e26c3b5240da51707b328e19db6b00a42eea46aee47a63f274b7cbc89c.sig
    ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:sha256-527c74ad60fb86a15c6d16acccddab6864f98d5a4cd62e5a8bde9548b5012083.sig
    ghcr.io/kubewarden/policies/sysctl-psp:sha256-300d9e5cb09f475003b27c7df573864b85101e48f62befcaf385f9e44c939986.sig
    ghcr.io/kubewarden/policies/allowed-fsgroups-psp:sha256-c782569518aa3d31733848f24c85b42b72ea490cea451da21195297653575301.sig
    ghcr.io/kubewarden/policies/host-namespaces-psp:sha256-ee286061edb4e52e134c9594312a98d2aebded5569f39d419bb891761f532449.sig
    ghcr.io/kubewarden/policies/host-namespaces-psp:sha256-ee286061edb4e52e134c9594312a98d2aebded5569f39d419bb891761f532449.sig
    ghcr.io/kubewarden/policies/host-namespaces-psp:sha256-ee286061edb4e52e134c9594312a98d2aebded5569f39d419bb891761f532449.sig
    ghcr.io/kubewarden/policies/host-namespaces-psp:sha256-ee286061edb4e52e134c9594312a98d2aebded5569f39d419bb891761f532449.sig
    ghcr.io/kubewarden/policies/pod-privileged:sha256-6f98a566c889e1313f0f00795f3080880eaa9ed44579135bcc0e664fa6848b37.sig
    ghcr.io/kubewarden/policies/readonly-root-filesystem-psp:sha256-7840099b5b21c2ec6b35d5f0603e36d8403759c3713591df7f9cb770389e6259.sig
    ghcr.io/kubewarden/policies/capabilities-psp:sha256-55ee09e26c3b5240da51707b328e19db6b00a42eea46aee47a63f274b7cbc89c.sig
    ghcr.io/kubewarden/policies/user-group-psp:sha256-f5fd26e3bdfd511819d7d57dae23a244a25aadfc7870d8fabd3bbfc447d4d02c.sig
    ghcr.io/kubewarden/policies/user-group-psp:sha256-f5fd26e3bdfd511819d7d57dae23a244a25aadfc7870d8fabd3bbfc447d4d02c.sig
    ghcr.io/kubewarden/policies/selinux-psp:sha256-9ad67ecaa64bc581cb9be3423a58a750862077ad436dfe058871bd33f73b298f.sig
    ghcr.io/jvanz/policies/seccomp-psp:sha256-6f54c659bcde2c44f8419d197ac8bb777798a2bf7d2b1c3088e2c7352e766b3e.sig
    ghcr.io/kubewarden/policies/user-group-psp:sha256-f5fd26e3bdfd511819d7d57dae23a244a25aadfc7870d8fabd3bbfc447d4d02c.sig
)

for IMAGE in "${IMAGES[@]}"
do
  replace_files_with_latest_tag "${IMAGE}"
done