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
tika_server = "http://192.168.169.138:9998/tika"
es_server = "http://localhost:9200"
index_name = "index-document"
indexation_dir = "/mnt/DOCUMENTS_A_INDEXER"
indexes_dir = "/mnt/DOCUMENTS_INDEXES"
non_indexes_dir = "/mnt/DOCUMENTS_NON_INDEXES"
df = pandas.DataFrame(columns = ("name", "content", "metadata", "document_type", "download_link"))
# create a client instance of the library
elastic_client = Elasticsearch(http_compress=True)
# index du dataframe
i = 1
for pdf in os.listdir(indexation_dir):
    file_name = indexation_dir + '/' +  pdf
    download_link = '\\\\192.168.169.128\\' + pdf
    extension = pdf.split(".")[1]
    if extension == "pdf":
        content = ""
        parsed = ""
        document_type = "pdf"
        try:
            parsed = parser.from_file(file_name, tika_server)
            metadata = parsed["metadata"]
            content = parsed["content"]
            df.loc[i] = file_name, content, metadata, document_type, download_link
        #On ajoute ensuite 1 à chaque itération pour indexer un autre document
            i += 1
        except Exception as exc:
            print (exc)
            shutil.move(file_name, non_indexes_dir)
    if extension == "docx":
        content = ""
        parsed = ""
        document_type = "docx"
        try:
            parsed = parser.from_file(file_name, tika_server)
            metadata = parsed["metadata"]
            content = parsed["content"]
            df.loc[i] = file_name, content, metadata, document_type, download_link
        #On ajoute ensuite 1 à chaque itération pour indexer un autre document
            i += 1
        except Exception as exc:
            print (exc)
            shutil.move(file_name, non_indexes_dir)
    if extension == "pptx":
        content = ""
        parsed = ""
        document_type = "pptx"
        try:
            parsed = parser.from_file(file_name, tika_server)
            metadata = parsed["metadata"]
            content = parsed["content"]
            df.loc[i] = file_name, content, metadata, document_type, download_link
        #On ajoute ensuite 1 à chaque itération pour indexer un autre document
            i += 1
        except Exception as exc:
            print (exc)
            shutil.move(file_name, non_indexes_dir)
for index, row in df.iterrows():
    filepath = row['name']
    op_dict = {
    	"index": {
	    "_index": index_name,
	    "content": row['content'],
	    "name": row['name'],
	    "metadata": row['metadata'],
	    "document_type": row['document_type'],
	    "download_link": row['download_link']
	}
    }
    try:
        elastic_client.index(index = index_name, body = op_dict)
        filename = filepath.split('/')[-1]
        index_file_path = indexes_dir + '/' + filename 
        shutil.move(filepath, index_file_path) 
        #helpers.bulk(elastic_client, [op_dict])
    except Exception as e:
        print (e)
        filename = filepath.split('/')[-1]
        non_index_file_path = non_indexes_dir + '/' + filename 
        shutil.move(filepath, non_index_file_path) 
