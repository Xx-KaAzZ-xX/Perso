#!/usr/bin/env python
# coding: utf-8

from elasticsearch import Elasticsearch
from elasticsearch import helpers


# configure elasticsearch
es = Elasticsearch(httpCompress=True)
index = "index-document"
request_body = {
	"settings" : {
		"number_of_shards": 1,
	        "number_of_replicas": 1
	    },

	    'mappings': {
	        "_source": {
	            "excludes": [
	                "content",
	                "index.content"
	            ]
	        },
	         'properties': {
	            'name': {
	                'type': 'text'
	                },
	            'metadata': {
	                'type': 'text'
	                },
                    'document_type': {
	                'type': 'text'
	                },

	            'content': {
	                'type': 'text',
	                'store': True
	                }
	          }
	         }
	}
print("creating [" + index +"]  index...")
es.indices.create(index = index, body = request_body)
