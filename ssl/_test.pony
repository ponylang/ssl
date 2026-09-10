use "pony_test"

use crypto = "./crypto"

actor \nodoc\ Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)

  fun tag tests(test: PonyTest) =>
    crypto.Main.make().tests(test)
