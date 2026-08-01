## Fix SSL sessions returning uninitialized memory

`SSL.read` and `SSL.send` could return uninitialized memory. They no longer do.
