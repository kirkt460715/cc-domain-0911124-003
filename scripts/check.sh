#!/bin/sh
set -eu
python3 -m compileall -q rights_graph
python3 -m unittest discover -s tests -v
python3 -m rights_graph --db :memory: demo --fixture fixtures/demo.json
