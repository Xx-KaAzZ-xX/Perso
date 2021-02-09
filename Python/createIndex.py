#!/usr/bin/env python
# coding: utf-8

from elasticsearch import Elasticsearch
from elasticsearch import helpers


# configure elasticsearch
es = Elasticsearch(httpCompress=True)
request_body = {
        "settings" : {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },

            'mappings': {
                 'properties': {
                    'name': {'type': 'text'},
                    'metadata': {'type': 'text'},
                    'content': {'type': 'text'},
                  }}
        }
print("creating 'example_index' index...")
es.indices.create(index = 'index-pdf', body = request_body)
