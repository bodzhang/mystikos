#!/bin/bash

while read -r file; do
   if [[ -e "appdir/coreclr-tests-all/$file" ]]
   then
      echo $file >> pr1-only-list
   else
      echo "appdir/coreclr-tests-all/$file not found!"
   fi
done < pr1-only-tests