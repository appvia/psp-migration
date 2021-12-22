import * as k8s from '@kubernetes/client-node'
import * as yaml from 'js-yaml'
import { createHash } from 'crypto'

import { transform_gatekeeper } from './gatekeeper'
import { transform_kyverno } from './kyverno'
import { transform_kubewarden } from './kubewarden'

import * as mod from './index'

export function parse(string: string): k8s.V1beta1PodSecurityPolicy {
  return yaml.load(string) as k8s.V1beta1PodSecurityPolicy
}

export function transform(PSP: k8s.V1beta1PodSecurityPolicy, engine: string): object[] {
  if (engine === 'gatekeeper')
    return transform_gatekeeper(PSP).map(mod.unique_names)

  if (engine === 'kyverno')
    return transform_kyverno(PSP).map(mod.unique_names)

  if (engine === 'kubewarden')
    return transform_kubewarden(PSP).map(mod.unique_names)

  throw new Error(`Unknown engine ${engine}`)
}


export function unique_names(obj: object): object {
  const hash = createHash('sha256').update(JSON.stringify(obj)).digest('hex').substring(0, 5).toLowerCase()
  //@ts-expect-error
  obj.metadata.name = `${obj.metadata.name}-${hash}`
  return obj
}