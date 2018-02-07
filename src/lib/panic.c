

/**
 * Handler for fatal errors.
 */
MHD_PanicCallback mhd_panic = NULL;

/**
 * Closure argument for #mhd_panic.
 */
void *mhd_panic_cls = NULL;


/**
 * Sets the global error handler to a different implementation.  @a cb
 * will only be called in the case of typically fatal, serious
 * internal consistency issues.  These issues should only arise in the
 * case of serious memory corruption or similar problems with the
 * architecture.  While @a cb is allowed to return and MHD will then
 * try to continue, this is never safe.
 *
 * The default implementation that is used if no panic function is set
 * simply prints an error message and calls `abort()`.  Alternative
 * implementations might call `exit()` or other similar functions.
 *
 * @param cb new error handler
 * @param cls passed to @a cb
 * @ingroup logging
 */
void
MHD_set_panic_func (MHD_PanicCallback cb,
                    void *cls)
{
  mhd_panic = cb;
  mhd_panic_cls = cls;
}
