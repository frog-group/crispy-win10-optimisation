Intelligent standby list cleaner (ISLC) is a lightweight application designed to help you monitor and clear the memory standby list.

ISLC command lines:
-minimized                                 --> Start ISLC minimized and auto-start monitoring
-polling "your value without quote"        --> Set the Memory polling Rate(ms) for ISLC
-listsize "your value without quote"       --> Purge Standbylist when list size is at this value
-freememory "your value without quote"     --> Purge Standbylist when freememory is at this value
-runonce                                   --> Only poll once and then exit.

"-listsize" and "-freememory" work in pair. if both are not specified, it will take the default value in the config file.
"-polling" is ignored when "-runonce" is specified.


Example:   -minimized -polling 500 -listsize 1024 -freememory 1024

Note: If ISLC detect that the Performance Counters are disabled in the Registry, it will automatically re-Enable them.

Usual fixes for ISLC when there is errors:

First : Run in a CMD (command prompt with admin privilege) 2 times :
LODCTR /R and reboot

If still not working, we check if you have disabled performance counter and enable them

lodctr /q | find "Disabled"

lodctr /e:PerfOS

Probably need a reboot.
