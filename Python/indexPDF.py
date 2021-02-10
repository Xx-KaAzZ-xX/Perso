#!/usr/bin/env python
# coding: utf-8

import tika
import requests
import pandas
import os
import string
import shutil
from tika import parser
from elasticsearch import Elasticsearch, helpers


##Définition des variables
tika_server = "http://192.168.2.25:9998/tika"
es_server = "http://localhost:9200"
index = "index-pdf"
pdf_dir = "/home/anon/test"
indexes_dir = "/home/anon/DOCUMENTS_INDEXES"
non_indexes_dir = "/home/anon/DOCUMENTS_NON_INDEXES"
df = pandas.DataFrame(columns = ("name", "content", "metadata"))
# create a client instance of the library
elastic_client = Elasticsearch(http_compress=True)
# index du dataframe
i = 1
for pdf in os.listdir(pdf_dir):
    file_name = pdf_dir + '/' +  pdf
    extension = pdf.split(".")[1]
    if extension == "pdf":
        content = ""
        parsed = ""
        parsed = parser.from_file(file_name, tika_server)
        metadata = parsed["metadata"]
        content = parsed["content"]
        df.loc[i] = file_name, content, metadata
        #On ajoute ensuite 1 à chaque itération pour indexer un autre document
        i += 1
for index, row in df.iterrows():
    filepath = row['name']
    op_dict = {
        "index": {
            "_index": 'index-pdf',
            "_type": 'pdf',
            "content": row['content'],
            "name": row['name'],
            "metadata": row['metadata']
        }
    }
    try:
        elastic_client.index(index = 'index-pdf', body = op_dict)
        filename = filepath.split('/')[-1]
        index_file_path = indexes_dir + '/' + filename
        shutil.move(filepath, index_file_path)
        #helpers.bulk(elastic_client, [op_dict])
    except Exception as e:
        print (e)
        filename = filepath.split('/')[-1]
        non_index_file_path = non_indexes_dir + '/' + filename
        shutil.move(filepath, non_index_file_path)
