#ifndef _CAPSICUM_RIGHTS_H
#define _CAPSICUM_RIGHTS_H

void cap_rights_regularize(struct capsicum_rights *rights);
struct capsicum_rights *cap_rights_set_all(struct capsicum_rights *rights);
bool cap_rights_contains(const struct capsicum_rights *big,
			 const struct capsicum_rights *little);
bool cap_rights_is_all(const struct capsicum_rights *rights);

#endif /* _CAPSICUM_RIGHTS_H */
