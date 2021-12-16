# log4shell_fix 
finding Java executables affected by "Log4Shell" log2j JNDI exploit;

optionally, fix them by removing the vulnerable class.

# context
In December 2021, a JNDI-exploit in log4j was found, rated as "critical" CVE-2021-44228. 
It is also known as "Log4Shell".

Soon thereafter, the proposed preliminary fix by applying an environment variable was found
insufficient, see CVE-2021-45046.

The stable alternative is to remove the log4j class JndiLookup from all archives.
But which archives are those?

This bash script scans a given path recursively for archive types (JAR, WAR, EAR, ZIP), 
and within for the risky class. It reports findings, and there is also an option
for automated removal.

Removing said class should, according to the [Apache docs](https://logging.apache.org/log4j/2.x/security.html), 
provide a fix without affecting the regular functionality of the logging class.
But doing so, whether using this script, or manually, is done at your own risk.


A more permanent solution is to update all software which uses log4j to at log4j2 version 2.16.0 or later (Java7 to 2.12.2).


# License
This software is placed under a [CC-BY-SA 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/legalcode).
It is (c) 2021 Tarja, all rights reserved.

# Requirements
* an unixoid OS
* bash shell
* zip executable
* unzip executable

# Usage
1. copy to the filesystem in question
2. log in as account with sufficient rights to access all files to be searched
3. execute script, giving the path to be searched as parameter (default is "/")

Example way to obtain:

    $ wget https://raw.githubusercontent.com/tarja1/log4shell_fix/main/removeJndiFromLog4j.bash

Example usage to scan a path (defaults to /):

    $ bash removeJndiFromLog4j.bash /path/to/scan
    
Example: scan entire filesystem, log results to file, showing progress

    $ bash removeJndiFromLog4j.bash -v / >log4shell_scanresults

Output lines marked "WARNING" will tell you where the risk is found, 
or where the script encountered issues in its operation (e.g. nested archives).
Lines marked "NOTICE" give you additional information where related issues were found.

If verbose mode is activated, the files being worked on are shown. Otherwise, 
the script performs silently unless there is something to report.


