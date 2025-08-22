#!/usr/bin/env bash
set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U pip
pip install -U -r requirements.txt 
cd docs
make html
touch _build/html/.nojekyll
if [  -d "./../mailsuite-docs" ]; then
  cp -rf _build/html/* ../../mailsuite-docs/
fi
cd ..
ruff check
rm -rf dist/ build/
hatch build
