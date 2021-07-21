# epfl_roaming and manage_cred


## `manage_cred`

... is a tool that receives user's credentials during authentication phase and keeps it for later use.
Any tool that want to benefit from it has to implement a "manage_cred's extension" by adding a Python file in `/usr/local/lib/manage_cred/` that implements both :
1. `FLAG_FILE` : points to a file that reports that this extension expects to be run
2. `run` : function that will receive both the username and the password in order to perform the commands needing the credentials.

The files related to manage_cred :
+ `/etc/pam.d/common-auth`
    Says that PAM has to run `manage_cred.py` at authentication step with credentials exposed
+ `/usr/local/bin/manage_cred.py`
    Main script
+ `/usr/local/lib/manage_cred`
    Folder that will contain all extensions


## `epfl_roaming`

... is a tool that stores selected application's config/preferences on the NAS. This is configured by adding right the folders, files and DConf keys in `/usr/local/etc/epfl_roaming.conf`.
With epfl_roaming, the users have a clean session (created from `/etc/skel`) at every login, plus the important application's settings available across all PCs in a classroom.
It directly needs `manage_cred`, since it has to mount the NAS during session creation at a time when we don't receive the password from PAM.

The files related to epfl_roaming :
+ `/etc/pam.d/common-session`
    Says that PAM has to run `epfl_roaming.py --pam` at session opening and closing. Most of the job is done here.
+ `/etc/skel/.config/autostart/epfl_roaming.desktop`
    Says that Gnome/Unity has to run `epfl_roaming.py --session` when session is opened (used to apply DConf keys)
+ `/etc/systemd/system/epfl_roaming_on_shutdown.service`
    Says that systemd has to run `epfl_roaming.py --on_halt` when the system is shut down or rebooted (since PAM procedure might be skipped or aborted)
+ `/usr/local/bin/epfl_roaming.py`
    Main script
+ `/usr/local/etc/epfl_roaming.conf`
    Configuration.
    This File has to be customized to :
    + replace the path `ChangeMeToResponsibleTeam/pool` to the expected one
    + choose what app's prefs have to be roaming
+ `/usr/local/lib/manage_cred/ext_epfl_roaming.py`
    manage_cred's extension for epfl_roaming


# How to do the setup

~~~ bash
sudo make install
~~~

Note : This process has been validated on Ubuntu 18.04. Adaptations will be needed for Ubuntu 14.04 or other GNU/Linux flavors.
