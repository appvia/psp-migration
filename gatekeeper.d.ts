import * as k8s from '@kubernetes/client-node';
export declare function transform_gatekeeper(PSP: k8s.V1beta1PodSecurityPolicy): object[];
export declare function gatekeeper_pod_policy_helper(kind: string, parameters?: object | null): object;
