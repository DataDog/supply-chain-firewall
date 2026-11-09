#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# [tool.uv]
# resolution = "lowest"
# allow-insecure-host = ["script.example"]
# find-links = ["wheels"]
# [[tool.uv.index]]
# url = "https://script.example/custom/"
# [tool.uv.sources]
# local-project = { path = "local-project" }
# ///
# A trailing comment must not change the metadata block.
print("script fixture")
