import * as k8s from '@kubernetes/client-node';
import * as yaml from 'js-yaml';

export function parse(string: string): k8s.V1beta1PodSecurityPolicy {
  return yaml.load(string) as k8s.V1beta1PodSecurityPolicy
}

