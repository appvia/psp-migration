import * as k8s from '@kubernetes/client-node';
export declare function parse(string: string): k8s.V1beta1PodSecurityPolicy;
export declare function transform(PSP: k8s.V1beta1PodSecurityPolicy, engine: string): object[];
export declare function unique_names(obj: object): object;
