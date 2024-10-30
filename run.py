# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from   flask_migrate import Migrate
from   flask_minify  import Minify
from   sys import exit
from apps.config import config_dict
from apps import create_app, db
import threading
import asyncio
import time
import sqlite3
import ast
import sys, os
import shutil

DB_FOLDER = "./apps/DB/"
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
# WARNING: Don't run with debug turned on in production!
DEBUG = (os.getenv('DEBUG', 'False') == 'True')

# The configuration
get_config_mode = 'Debug' if DEBUG else 'Production'

try:
    # Load the configuration using the default values
    app_config = config_dict[get_config_mode.capitalize()]
    
except KeyError:
    exit('Error: Invalid <config_mode>. Expected values [Debug, Production] ')

app = create_app(app_config)
Migrate(app, db)

if not DEBUG:
    Minify(app=app, html=True, js=False, cssless=False)
    
if DEBUG:
    app.logger.info('DEBUG            = ' + str(DEBUG)             )
    app.logger.info('Page Compression = ' + 'FALSE' if DEBUG else 'TRUE' )
    app.logger.info('DBMS             = ' + app_config.SQLALCHEMY_DATABASE_URI)

def get_source_from_id(customer,ID ):
    try:
        conn = sqlite3.connect(DB_FOLDER+'source.db')
        cur = conn.cursor()
        cur.execute("SELECT * FROM source WHERE customer=? and ID=?", (str(customer),str(ID),))
        rows = cur.fetchall()
        conn.close()
        tmp={}
        for row in rows:
            
            tmp["ID"]=row[0]
            tmp["source"]=row[1]
            tmp["source_name"]=row[2]
            tmp["conf_data"]=row[3]
            tmp["category"]=row[4]
            tmp["time"]=row[6]

        return tmp
    except:
        return -1


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
