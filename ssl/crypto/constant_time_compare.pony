primitive ConstantTimeCompare
  """
  Return true if the two `ByteSeq`s have equal contents. The time taken is
  independent of the contents, so comparing a secret against a value an
  attacker supplies does not tell them where the two first differ.

  ```pony
  if ConstantTimeCompare(expected_mac, supplied_mac) then
    // ...
  end
  ```

  Sequences of different sizes are not equal, and that is answered before any
  byte is read.
  """
  fun apply[S: ByteSeq box = ByteSeq box](xs: S, ys: S): Bool =>
    if xs.size() != ys.size() then
      false
    else
      var v = U8(0)
      var i: USize = 0
      while i < xs.size() do
        try
          v = v or (xs(i)? xor ys(i)?)
        else
          return false
        end
        i = i + 1
      end
      v == 0
    end
