import * as k8s from '@kubernetes/client-node';
export declare class ClusterPolicy {
    apiVersion?: string;
    kind?: string;
    metadata?: k8s.V1ObjectMeta;
    spec?: any;
    constructor(name: string, mutate?: boolean);
    addRule(rule: any): void;
}
export declare function optional_ephemeral_init_container_copy(obj: object): {
    "=(initContainers)": object[];
    "=(ephemeralContainers)": object[];
    containers: object[];
};
export declare function wrap_validate_spec(obj: object): object;
export declare function transform_kyverno(PSP: k8s.V1beta1PodSecurityPolicy): object[];
