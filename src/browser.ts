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
  const provided = document.getElementById("in")?.value

  let outputs = ""
  //@ts-expect-error
  engines.forEach(engine => outputs += `## ${engine}: \n \`\`\`yaml${document.getElementById(engine).value}\`\`\`\n`)

  const body = `
# Please describe the bug you encountered.

# What did you do?

# What did you expect to see?

# What did you see instead?

# Input:
\`\`\`yaml
${provided}
\`\`\`

# Output:
${outputs}
`
  window.open(`https://github.com/appvia/psp-migration/issues/new?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`)
}

document.getElementById("in")?.addEventListener("input", process)
document.getElementById("bugreport")?.addEventListener("click", bugReport)