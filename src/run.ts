import { readFileSync } from 'fs'
import * as yaml from 'js-yaml'

const psp = readFileSync(0, 'utf-8')

import { parse, transform } from './index'

const parsed = parse(psp)
const transformed = transform(parsed, 'gatekeeper')

const yamlString = transformed.map(policy => yaml.dump(policy)).join('\n---\n')

process.stdout.write(yamlString)