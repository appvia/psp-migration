import 'materialize-css'

import "./styles.scss"

import * as ace from 'ace-builds'
import 'ace-builds/webpack-resolver'

import * as yaml from 'js-yaml'

import { parse, transform } from './index'

const engines = ['gatekeeper', 'kyverno', 'kubewarden']

window.M.Tabs.init(jQuery(".tabs"))
window.M.FormSelect.init(jQuery("select"), {})

let editors: any = {}

const editorDefault = {
  mode: "ace/mode/yaml",
  theme: "ace/theme/crimson_editor",
  tabSize: 2,
  useSoftTabs: true,
}

engines.forEach(engine => editors[engine] = ace.edit(engine, {
  ...editorDefault,
  readOnly: true,
}))


function process() {
  engines.forEach(engine => {
    try {
      let code = transform(parse(editor.getValue()), engine)
        .map(policy => yaml.dump(policy, { noRefs: true, quotingType: '"' }))
        .join('\n---\n')
      editors[engine].setValue(code)
      editors[engine].clearSelection()
    }
    catch (e) {
      console.error(e)
      //@ts-expect-error
      editors[engine].setValue(e.message)
    }
  })
}

function bugReport() {
  const title = "Bug Report from web-ui"
  const bugurl = new URL("https://github.com/appvia/psp-migration/issues/new")

  bugurl.searchParams.append("template", "bugfromweb.yaml")
  bugurl.searchParams.append("title", title)

  //@ts-expect-error
  bugurl.searchParams.append("version", [COMMIT_SHA])

  //@ts-expect-error
  bugurl.searchParams.append("input", [editor.getValue()])

  //@ts-expect-error
  engines.forEach(engine => bugurl.searchParams.append(`${engine}-yaml`, [editors[engine].getValue()]))

  window.open(bugurl.href)
}

document.getElementById("bugreport")?.addEventListener("click", bugReport)

const editor = ace.edit("editor", {
  ...editorDefault,
  value: `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: policy
spec:
  privileged: false
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  volumes:
    - '*'`
})


editor.on("change", process)
process()

document.getElementById("upload")?.addEventListener("change", () => {
  //@ts-expect-error
  const [file] = document.querySelector('input[type=file]').files
  const reader = new FileReader()

  reader.addEventListener("load", () =>
    editor.setValue(reader.result as string))

  if (file)
    reader.readAsText(file)
})

document.getElementById("example-select")?.addEventListener("change", () => {
  //@ts-expect-error
  const originalURL: string = document.getElementById("example-select")?.value
  const url = originalURL
    .replace("github.com", "raw.githubusercontent.com")
    .replace("/blob/", "/")
  fetch(url)
    .then(response => response.text())
    .then(text => yaml.loadAll(text)
      .filter((x: any) => x.kind === 'PodSecurityPolicy')[0])
    .then(yaml.dump)
    .then(data => editor.setValue(`# ${originalURL} \n${data}`));
})