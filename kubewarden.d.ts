import * as k8s from '@kubernetes/client-node';
export declare function transform_kubewarden(PSP: k8s.V1beta1PodSecurityPolicy): object[];
export declare function kubewarden_policy_helper(name: string, module: string, settings?: any, mutating?: boolean): {
    apiVersion: string;
    kind: string;
    metadata: {
        name: string;
    };
    spec: {
        module: string;
        rules: {
            apiGroups: string[];
            apiVersions: string[];
            resources: string[];
            operations: string[];
        }[];
        mutating: boolean;
        settings: any;
    };
};
