#!/bin/bash
git pull
cd ../mailsuite-docs || exit
git pull
cd ../mailsuite || exit
./build.sh
cd ../mailsuite-docs || exit
git add .
git commit -m "Update docs"
git push
