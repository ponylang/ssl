use "pony_test"

use crypto = "./crypto"
use net = "./net"

actor \nodoc\ Main is TestList

  new create(env: Env) =>
    PonyTest(env, this)

  fun tag tests(test: PonyTest) =>
    crypto.Main.make().tests(test)
    net.Main.make().tests(test)
