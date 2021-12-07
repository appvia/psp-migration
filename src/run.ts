import { readFileSync } from 'fs'
import * as yaml from 'js-yaml'

import yargs from 'yargs'

const options = yargs
  .usage("Usage: -e <engine>")
  .option("engine", {
    alias: "e",
    describe: "Policy Engine, must be of [gatekeeper|...]",
    type: "string",
    demandOption: true
  })
  .argv


const psp = readFileSync(0, 'utf-8')

import { parse, transform } from './index'

const parsed = parse(psp)

//@ts-ignore
const transformed = transform(parsed, options.engine)

const yamlString = transformed.map(policy => yaml.dump(policy)).join('\n---\n')

process.stdout.write(yamlString)