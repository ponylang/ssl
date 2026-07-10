## Allow non-mutating methods to be called on a val receiver

`SSLContext.get_min_proto_version`, `SSLContext.get_max_proto_version` and `SSL.can_send` read their receiver and change nothing, but each was declared `fun ref`, which a `val` receiver cannot call.

That mattered for the getters, because configuring a context and then holding it `val` is what `SSLContext.client` and `SSLContext.server` require, so neither getter could be called on the context shape you end up with:

```pony
let ctx =
  recover val
    SSLContext .> set_authority(auth_file)?
  end

// Before: does not compile.
// After: reads the minimum the context was configured with.
let minimum = ctx.get_min_proto_version()
```

All three now take any receiver. Code that already called them on a mutable receiver needs no change.
