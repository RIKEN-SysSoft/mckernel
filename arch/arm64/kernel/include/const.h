/* const.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_CONST_H
#define __HEADER_ARM64_COMMON_CONST_H

#ifndef __ASSEMBLY__
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#else /* !__ASSEMBLY__ */
#define _AC(X,Y)	X
#define _AT(T,X)	X
#endif /* !__ASSEMBLY__ */

#define _BITUL(x)	(_AC(1,UL) << (x))
#define _BITULL(x)	(_AC(1,ULL) << (x))

/*
 * Allow for constants defined here to be used from assembly code
 * by prepending the UL suffix only with actual C code compilation.
 */
#define UL(x) _AC(x, UL)

#endif /* !__HEADER_ARM64_COMMON_CONST_H */
