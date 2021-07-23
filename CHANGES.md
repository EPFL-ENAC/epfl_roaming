# Version 0.4.0

Replace fuse-ext2 for the (IC-centric) POSIX environment with [posixovl](http://manpages.ubuntu.com/manpages/bionic/man1/mount.posixovl.1.html).

Rather than an opaque 1G blob in their Windows® share, users of the POSIX environment will now be able to see their files on a Windows® / CIFS mount as usual (except of course that fine-grained permissions are unavailable this way).

As a backward compatibility measure, the old 1G blob will still get mounted if found. This affords users a migration path going like this:
- Back up (e.g with tar) the content of your posixfs into somewhere persistent, e.g. Desktop/myfiles/myposix.tar
- Delete the loopback file
- Log out and back in
- Restore backup
