import 'materialize-css'

import "./styles.scss"

import * as yaml from 'js-yaml'

import hljs from 'highlight.js/lib/core'
import yamllang from 'highlight.js/lib/languages/yaml'

hljs.registerLanguage('yaml', yamllang)

import { parse, transform } from './index'

const engines = ['gatekeeper', 'kyverno', 'kubewarden']

window.M.Tabs.init(jQuery(".tabs"))

function process() {
  engines.forEach(engine => {
    try {
      //@ts-expect-error
      let code = transform(parse(document.getElementById("in").value), engine)
        .map(policy => yaml.dump(policy, { noRefs: true, quotingType: '"' }))
        .join('\n---\n')
      //@ts-expect-error
      document.getElementById(engine).innerHTML = hljs.highlight(code, { language: 'yaml' }).value
    }
    catch (e) {
      console.error(e)
      //@ts-expect-error
      document.getElementById(engine).innerHTML = e.message
    }
  })
}

process()

function bugReport() {
  const title = "Bug Report from web-ui"

  const bugurl = new URL("https://github.com/appvia/psp-migration/issues/new")

  bugurl.searchParams.append("template", "bugfromweb.yaml")
  bugurl.searchParams.append("title", title)

  //@ts-expect-error
  bugurl.searchParams.append("input", [document.getElementById("in")?.value])
  //@ts-expect-error
  engines.forEach(engine => bugurl.searchParams.append(`${engine}-yaml`, [document.getElementById(engine)?.textContent]))

  window.open(bugurl.href)
}

document.getElementById("in")?.addEventListener("input", process)
document.getElementById("bugreport")?.addEventListener("click", bugReport)