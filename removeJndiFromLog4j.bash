#!/bin/bash
# fix for CVE-2021-45046 and CVE-2021-44228: removing all instances of the "guilty" JNDI class, systemwide.
# (c) Tarja 2021, all rights reserved - License: CC-BY-SA 4.0
# Version 1.0.0 alpha

# path to scan from first parameter. default: entrire filesystem
PATH_TO_SCAN=/

# report only, or remove where found?
# regexp for filenames to scan for.
FILE_EXTENSIONS_PATTERN=".*\.\(jar\|war|ear|zip\)$"
# no .cap files; also, we risk breaking signed JARs.

verbose=false
perform_delete=false

# when we've found an JndiLookup.class, what to do about it
handleDangerFound()
{
 filename=$1
 filenameInArchive=$2

 # check it is actually the log4j one, not e.g. com/intellij/spring/model/xml/jee/JndiLookup.class or io/sentry/config/JndiLookup.class
 # precise match required
 if [[ $filenameInArchive =~ ^org/apache/logging/log4j/core/lookup/JndiLookup.class$ ]];
 then
    echo "NOTICE: found the dangerous $filenameInArchive in file $filename"
    # add -q unless verbose
# detecting signed JARs by this heuristic:
# - if they don't contain a META-INF/MANIFEST.MF, they can't be signed
# - if their manifest contains at least one Digest line, they're signed.
# we have to skip them. changes would break things.
      manifest=$(unzip -p $filename META-INF/MANIFEST.MF)
      if echo "$manifest" | grep -q -wi Digest; then
        echo "ERROR: Signed JAR, can't change it without breaking: \"$filename\""
        return
      fi
    if $perform_delete; then
    # perform the actual delete
      zip -d "$filename" "$filenameInArchive"
    fi
 # see "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class"
 else
    echo "WARNING: found $filenameInArchive in file $filename"
 fi
}

# we found a JAR inside an archive
# as of now, we can just check and report.
handleArchiveRecursion()
{
 filename=$1
 filenameInArchive=$2

 if $verbose; then
   echo "WARNING: nested archive - $filenameInArchive in $filename"
 fi
 # optional recursion
 # matching log4j specifically
 if [[ $filenameInArchive =~ ^log4j-core*.jar$ ]];
 then
    echo "WARNING: log4j JAR found inside another archive $filename. no automated cleanup possible as of now"
 fi
}


# check a single archive file, change if needed and possible
scanAndCleanFile()
{
 recursion_files=
 filename=$1
 if $verbose;
 then
    >&2 echo "scanning file $1"
 fi;

 zip -T -sf "$1" | while IFS= read -r tempFilename; # @TODO optimise
     do
       # trim leading whitespace leftover by zip
       filenameInArchive=$(echo "$tempFilename"|xargs)
       # match contained filename to end in .class
       if [[ $filenameInArchive =~ JndiLookup\.class$ ]]
       then
         handleDangerFound "$filename" "$filenameInArchive"
         recursion_files="$recursion_files $filenameInArchive"
       fi

       # match JAR files inside other archives
       # other types are possible in theory, but haven't been reported anywhere (please provide a sample if you do)
       if [[ $filenameInArchive =~ .jar$ ]]
       then handleArchiveRecursion "$filename" "$filenameInArchive"
       fi
 done
}

usage()
{
  echo "Usage: $0 [-h | --help] [-V | --version] [-v | --verbose] [-d | --delete] [directory]" 1>&2
  echo "Version: 1.0.0 alpha" 1>&2
  echo "(c) Tarja 2021, all rights reserved - License: CC-BY-SA 4.0" 1>&2
  echo "purpose: finding all Java archives affected by log4j-JNDI issues CVE-2021-45046 and CVE-2021-44228" 1>&2
  echo "use --verbose for progress output" 1>&2
  echo "use --delete to perform changes to JAR files (at your own risk)." 1>&2
  exit $1
}

# ----- script execution entry point -----

if ! which zip >/dev/null 2>&1; then
  echo "zip tool is required in PATH, please install" 1>&2
  exit 1
fi
if ! which unzip >/dev/null 2>&1; then
  echo "unzip tool is required in PATH, please install" 1>&2
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help|-V|--version) usage 0; ;;
    -v|--verbose) verbose=true; ;;
    -d|--delete) perform_delete=true; ;;
    -*) echo "Unknown option $1"; usage 1; ;;
    *) PATH_TO_SCAN="$1"; ;;
  esac
  shift
done

# main loop: scan for suspect files
LANG= find "$PATH_TO_SCAN" -type f -regex "$FILE_EXTENSIONS_PATTERN" -print0 2> >(grep -v 'Permission denied' >&2) | while IFS= read -r -d '' file;
do
    scanAndCleanFile "$file"
done
# end of script
