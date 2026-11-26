TailConnect-SSH for Windows
===========================

Puts this PC on your TailConnect-SSH network: it gets an address and a name,
reaches your other machines directly or through the hub (SSH inside TLS on
port 443), and resolves their names (MagicDNS) in every program.

Requirements: Windows 10 (2004 or later) or Windows 11, 64-bit; an
administrator account to install and to log in or out.

Install or upgrade
------------------
Double-click install.cmd and accept the Windows prompt. It installs to
C:\Program Files\TailConnect-SSH:

  * the TailConnectSSH service (starts with Windows, restarts if it fails);
  * the TailConnect-SSH app: in the Start menu, by the clock at sign-in,
    and in Settings > Apps, where it can be uninstalled;
  * tcs, the command line (on the PATH of new command prompts);
  * firewall rules for peers' direct connections and the tunnel.

Running install.cmd again upgrades in place and keeps this PC logged in.

Join your network
-----------------
In the app (click the icon by the clock), choose "Log in...", and enter the
hub's address and an auth key from its web portal (or from
`tcs-control authkey create` on the hub). For a hub with a self-signed
certificate, also enter its TLS fingerprint (`tcs-control fingerprint`).

Or, in an administrator command prompt:

  tcs up --server HUB --authkey KEY [--tls-fingerprint FINGERPRINT]

Using it
--------
  tcs status            this PC, the other machines, and the path to each
  tcs ip NAME           a machine's address
  tcs down / tcs up     disconnect / reconnect (any signed-in user)
  tcs up --exit-node N  send internet traffic through machine N ("" stops)
  tcs logout            disconnect and forget the hub (administrator)

Machines answer to NAME (in your account) and NAME.ACCOUNT.DOMAIN.

Uninstall
---------
Settings > Apps > TailConnect-SSH > Uninstall, or in an administrator
command prompt: tcd uninstall (add --purge to delete this PC's keys too).

Files
-----
Keys, settings and the service's log (tcd.log) are in
C:\ProgramData\TailConnect-SSH, readable only by administrators.

wintun.dll is the Wintun network driver by WireGuard LLC (see
LICENSE-wintun.txt).
