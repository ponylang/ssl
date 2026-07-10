use @pony_os_stderr[Pointer[U8]]()
use @fprintf[I32](stream: Pointer[U8] tag, fmt: Pointer[U8] tag, ...)
use @exit[None](status: I32)

primitive _Unreachable
  """
  Panic for a code path that should be structurally impossible.

  Print the file, line, and method to stderr, then exit. Use it in the `else`
  of a `try`
  whose error the surrounding code has already ruled out, so that if the
  impossible ever does happen the program stops with a location instead of
  carrying on with the error swallowed.
  """
  fun apply(loc: SourceLoc = __loc) =>
    @fprintf(
      @pony_os_stderr(),
      "Unreachable code reached at %s:%lu in %s.%s\n".cstring(),
      loc.file().cstring(),
      loc.line(),
      loc.type_name().cstring(),
      loc.method_name().cstring())
    @fprintf(
      @pony_os_stderr(),
      "Please open an issue at https://github.com/ponylang/ssl/issues\n"
        .cstring())
    @exit(1)
