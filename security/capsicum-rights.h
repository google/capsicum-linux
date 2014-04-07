#ifndef _CAPSICUM_RIGHTS_H
#define _CAPSICUM_RIGHTS_H

#ifdef CONFIG_SECURITY_CAPSICUM
bool cap_rights_regularize(struct capsicum_rights *rights);
bool cap_rights_contains(const struct capsicum_rights *big,
			 const struct capsicum_rights *little);
#endif

#endif /* _CAPSICUM_RIGHTS_H */
