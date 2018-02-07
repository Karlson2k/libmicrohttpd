

#ifndef INIT_H
#define INIT_H

/**
 * Globally initialise library.
 */
void
MHD_init(void);


#ifdef _AUTOINIT_FUNCS_ARE_SUPPORTED
/**
 * Do nothing - global initialisation is
 * performed by library constructor.
 */
#define MHD_check_global_init_() (void)0
#else  /* ! _AUTOINIT_FUNCS_ARE_SUPPORTED */
/**
 * Check whether global initialisation was performed
 * and call initialiser if necessary.
 */
void
MHD_check_global_init_ (void);
#endif /* ! _AUTOINIT_FUNCS_ARE_SUPPORTED */


#endif  /* INIT_H */
