import * as mod from '../kyverno'
import * as yaml from 'js-yaml'
import * as fs from 'fs'

describe('f', () => {
  it.todo('should return true')
})

function help_load_psp(fixture: string) {
  const st = fs.readFileSync(`tests/${fixture}/psp.yaml`, { flag: 'r' })
  return yaml.load(st.toString())
}

// describe('transform_kyverno', () => {
//   it('foo', () =>
//     expect(mod.transform_kyverno(help_load_psp('allowPrivilegeEscalation'))).toMatchSnapshot()
//     // expect(mod.transform_kyverno(help_load_psp('allowPrivilegeEscalation'))).toBe({})
//   )
// })