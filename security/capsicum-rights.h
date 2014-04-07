#ifndef _CAPSICUM_RIGHTS_H
#define _CAPSICUM_RIGHTS_H

#ifdef CONFIG_SECURITY_CAPSICUM
void cap_rights_regularize(struct capsicum_rights *rights);
bool cap_rights_contains(const struct capsicum_rights *big,
			 const struct capsicum_rights *little);
bool cap_rights_has(const struct capsicum_rights *rights, u64 right);
#endif

#endif /* _CAPSICUM_RIGHTS_H */
