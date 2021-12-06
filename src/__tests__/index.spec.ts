// @global expect 
// jest.mock('../../src/index')
// jest.mock('../src/github')
// import * as google from '../src/google'
// import * as github from '../src/github'
import * as mod from '../index'

// let processExitSpy
// let consoleSpy

// beforeEach(() => {

// })

describe('missmatch', () => {
  // beforeEach(() => {
  // })
  it('should have consistent console output', async () => {
    console.log(mod)
    return expect(true).toBe(true)
  })

})