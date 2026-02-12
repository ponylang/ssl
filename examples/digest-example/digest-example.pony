// in your code this `use` statement would be:
// use "ssl/crypto"
use "../../ssl/crypto"

actor Main
  new create(env: Env) =>
    let sha256digest: Digest = Digest.sha256()
    try
      sha256digest.append("Hello ")?
      sha256digest.append("World")?
      let hash: Array[U8] val = sha256digest.final()
      env.out.print("SHA256: " + ToHexString(hash))
    else
      env.out.print("Error computing hash")
    end

    // SHAKE256 with variable-length output (OpenSSL 3.0.x only)
    ifdef "openssl_3.0.x" then
      let shake: Digest = Digest.shake256(64)
      try
        shake.append("Hello ")?
        shake.append("World")?
        let shake_hash: Array[U8] val = shake.final()
        env.out.print("SHAKE256 (64 bytes): " + ToHexString(shake_hash))
      else
        env.out.print("Error computing SHAKE hash")
      end
    end
