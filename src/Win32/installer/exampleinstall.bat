@echo off
REM Properties:
REM    
REM    LOGINURI:     Location of your login server
REM    KEYMGTURI:    Location of your pubookie key distribution server
REM    AUTHID1-3:    Names for your pubookie authentication flavors.  Use "" for unused flavors.
REM    RUNKEYCLIENT: 0=Do not run keyclient 1=Obtain new key (default) 2=Retrieve old key stored in keyserver for your application server

msiexec /i pubcookie.msi LOGINURI=https://weblogin.washington.edu KEYMGTURI=https://weblogin.washington.edu:2222 AUTHID1=UWNETID AUTHID2="" AUTHID3=SECURID RUNKEYCLIENT=1