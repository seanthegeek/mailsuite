#!/usr/bin/env bash
set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U -r requirements.txt 
cd docs
make html
touch _build/html/.nojekyll
cp -rf _build/html/* ../../mailsuite-docs/
cd ..
flake8 mailsuite
rm -rf dist/ build/
hatch build
