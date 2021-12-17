import * as yaml from 'js-yaml'

import { parse, transform } from './index'

const engines = ['gatekeeper', 'kyverno', 'kubewarden']

function process() {
  engines.forEach(engine => {
    try {
      //@ts-expect-error
      document.getElementById(engine).value = transform(parse(document.getElementById("in").value), engine)
        .map(policy => yaml.dump(policy, { noRefs: true, quotingType: '"' }))
        .join('\n---\n')
    }
    catch (e) {
      //@ts-expect-error
      document.getElementById(engine).value = e.message
    }
  })
}

process()

function bugReport() {
  const title = "Bug Report from web-ui"
  //@ts-expect-error
  window.open(`https://github.com/appvia/psp-migration/issues/new?template=bugfromweb.yaml&title=${encodeURIComponent(title)}&input=[${encodeURIComponent(document.getElementById("in")?.value)}]&gatekeeper-yaml=[${encodeURIComponent(document.getElementById("gatekeeper").value)}]&kyverno-yaml=[${encodeURIComponent(document.getElementById("kyverno").value)}]&kubewarden-yaml=[${encodeURIComponent(document.getElementById("kubewarden").value)}]`)
}

document.getElementById("in")?.addEventListener("input", process)
document.getElementById("bugreport")?.addEventListener("click", bugReport)