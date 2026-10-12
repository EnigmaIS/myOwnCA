"""Compatibility shim — dialect now lives in myownca-core."""
from myownca_core.storage.dialect import *  # noqa: F401,F403
from myownca_core.storage.dialect import prepare_ddl, translate_dml  # noqa: F401
