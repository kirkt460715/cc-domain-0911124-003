"""Distribution drift diagnostics run inside an authorization context.

The package compares two already-authorized data batches of the same source
asset.  It never reads columns that the context cannot read, never emits
row-level detail, and stores only aggregate diagnostics that are re-checked
against current grants and batch integrity on every read or export.
"""
