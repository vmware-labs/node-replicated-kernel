#!/bin/bash
set -o errexit -o nounset

cd book

rev=$(git rev-parse --short HEAD)

git init
git config user.name "Gerd Zellweger"
git config user.email "mail@gerdzellweger.com"

git remote add upstream "https://$GH_PAGES@github.com/gz/bespin.git"
git fetch upstream
git reset upstream/gh-pages

touch .
touch .nojekyll

git add -A .
git commit -m "rebuild pages at ${rev}"
git push -q upstream HEAD:gh-pages