"""Release verification bootstrap, independent of the CA and its database."""

import sys

# Bytecode is not part of the signed inventory. Never create unsigned caches.
sys.dont_write_bytecode = True
