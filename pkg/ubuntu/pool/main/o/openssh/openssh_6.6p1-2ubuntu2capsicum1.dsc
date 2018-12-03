-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: openssh
Binary: openssh-client, openssh-server, openssh-sftp-server, ssh, ssh-krb5, ssh-askpass-gnome, openssh-client-udeb, openssh-server-udeb
Architecture: any all
Version: 1:6.6p1-2ubuntu2capsicum1
Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
Uploaders: Colin Watson <cjwatson@debian.org>, Matthew Vernon <matthew@debian.org>
Homepage: http://www.openssh.org/
Standards-Version: 3.9.5
Vcs-Browser: http://anonscm.debian.org/gitweb/?p=pkg-ssh/openssh.git
Vcs-Git: git://anonscm.debian.org/pkg-ssh/openssh.git
Build-Depends: libwrap0-dev | libwrap-dev, zlib1g-dev (>= 1:1.2.3), libssl-dev (>= 0.9.8g), libpam0g-dev | libpam-dev, libgtk2.0-dev, libedit-dev, debhelper (>= 8.1.0~), libselinux1-dev [linux-any], libcaprights-dev (>= 0.1.0), libkrb5-dev | heimdal-dev, dpkg (>= 1.16.1~), libck-connector-dev, dh-autoreconf, autotools-dev, dh-systemd (>= 1.4)
Package-List: 
 openssh-client deb net standard
 openssh-client-udeb udeb debian-installer optional
 openssh-server deb net optional
 openssh-server-udeb udeb debian-installer optional
 openssh-sftp-server deb net optional
 ssh deb net extra
 ssh-askpass-gnome deb gnome optional
 ssh-krb5 deb oldlibs extra
Checksums-Sha1: 
 b850fd1af704942d9b3c2eff7ef6b3a59b6a6b6e 1282502 openssh_6.6p1.orig.tar.gz
 8d9a92973838d49bd8db53d51c322c5d2b638daf 241099 openssh_6.6p1-2ubuntu2capsicum1.debian.tar.gz
Checksums-Sha256: 
 48c1f0664b4534875038004cc4f3555b8329c2a81c1df48db5c517800de203bb 1282502 openssh_6.6p1.orig.tar.gz
 1df3596fa6578f7b7dc5831a0742ef2790f8cbc2b283619bc823d53732482c38 241099 openssh_6.6p1-2ubuntu2capsicum1.debian.tar.gz
Files: 
 3e9800e6bca1fbac0eea4d41baa7f239 1282502 openssh_6.6p1.orig.tar.gz
 68e8825de294a597b2030a77114edfb0 241099 openssh_6.6p1-2ubuntu2capsicum1.debian.tar.gz

-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iQIcBAEBCgAGBQJU2d38AAoJEHBBzKjvSyxQUB8P/080spOaGgSwY999wfFmhAWF
4Beynx3+D+JbTmHYQhyEyDwB/U5kjNY14KG05fTpKYyEbK3cNyjtwjb3R4AnBuC0
O1VZCczmna4K01yk+5HhB+OzC/Nwj8LDM2EOlzCodleYQUFWOx151n4sPy4+NLdJ
zDMZ32gxmrs++ws2ywGRsW1hbx6RfFwvUifS8p5QDiDyd6sxM0Ioi+odfX5D117g
9282TPWKjJEyF+nq1901JY1+6h0RYrd3pK2NQWXrMsGfGyoWOzlxBoP32WIKHdC9
DhsXEEvjKcUX4doeGnCBuqH2dqHIwimaWXDZRIqScQqiNp4ZZhLvGzPKwQWEmPDb
d/5iTSAVvyXfBOLBBNZjly1UvDKA69wsNq+dOC6X5PdpSCUBtojSW7l0hHwqIO4o
z1p8IsTp2UGoTJyzR3V1UhSmkcrfcgdXtJJQYMglOJ672x/mZx/Y6lF8T4YErQiT
wpbJ+FcKFj7PA5wriAE9rIGrvYWbp6gBac/Wm7/NinCw+x02fBEpraleS6VplJo5
jJThsZWk/0/19cSzjFpuv2CIFdc6vagF2S0J732/7DM+Pku23Hg+hmM3XHCBZO9o
0t4q1LJi1qi9wdKwzxFDLZ+Sc8z2VNrBvn1VpZxSXaN9CJCmf/Hgq1gEkS4Nv8w3
d+1n5dTZNj3ll4WumwR7
=9x5o
-----END PGP SIGNATURE-----
