Minion EV Check Plugin
=====================

This is a plugin for Minion which checks if the SSL certificate for a host was issued by an extended validation authority.

It currently only does the following checks

* Check if the Issuer of the site certificate contains an identifier for a known EV authority 

Important Note
--------------

The plugin does not perform any checks for the validity of the certificate nor the chain. 
