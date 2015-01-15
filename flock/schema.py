#!/usr/bin/python
# pylint: disable=missing-docstring
# pylint: disable=bad-continuation
# pylint: disable=too-many-arguments

import logging
import traceback
import struct
import simplejson as json
import re

from flock import record

logger = logging.getLogger('schema') # pylint: disable=invalid-name

class Schema(object):
    def __init__(self, sjson):
        obj = json.loads(sjson)
        if type(obj) is not dict:
            raise ValueError('DB defintion must be an object')
        if 'schema' not in obj:
            raise ValueError('DB missing schema')
        self.schema = obj['schema']
        self.indexes = []
        self.setup_str = self.__make_schema()
        if 'indexes' in obj:
            self.indexes = obj['indexes']
            self.setup_str += self.__make_indexes()
        self.delete_str = self.__make_deletes()

    def __make_schema(self):
        # Iterate over each table and make SQL to construct it
        if type(self.schema) is not dict:
            raise ValueError('Schema defintion must be an object')
        schema_str = ''
        for table, fields in self.schema.iteritems():
            schema_str += self.__make_table_def(table, fields) + ';\n'
        return schema_str

    def __make_deletes(self):
        # Iterate over each table and make SQL to construct it
        delete_str = ''
        for table, _ in self.schema.iteritems():
            delete_str += 'DROP TABLE ' + table + ';\n'
        #for idx in self.indexes:
        #    delete_str += 'DROP INDEX ' + '_'.join(idx) + ';\n'
        return delete_str

    def __make_indexes(self):
        if type(self.indexes) is not list:
            raise ValueError('Index defintions must be a list')
        # Iterate over each index and make SQL to construct it
        indexes_str = ''
        for idx in self.indexes:
            if type(idx) is not list:
                raise ValueError('Index defintion must be a list')
            if len(idx) < 2:
                raise ValueError('Index defintion needs table name + 1 field: ' + str(idx))
            table = idx[0]
            if type(table) is not str:
                raise ValueError('Table name must be a string')
            if table not in self.schema:
                raise ValueError('Table ' + table + ' is not in schema')
            for field in idx[1:]:
                if type(field) is not str:
                    raise ValueError('Field name must be a string')
                if field not in self.schema[table]:
                    raise ValueError('Field ' + field + ' not in table ' + table)
                if self.schema[table][field] == 'fulltext':
                    raise ValueError('Cannot index fulltext field ' + field + ' in ' + table)
            indexes_str += ('CREATE INDEX ' + '_'.join(idx) +
                ' ON ' + table + ' (' +
                ','.join(idx[1:]) + ');\n')
        return indexes_str

    def __make_table_def(self, table, fields):
        # Validate table name
        if type(table) is not str:
            raise ValueError('Table name must be a string')
        if not re.match('^[A-Za-z][_a-zA-Z0-9]*$', table):
            raise ValueError('Invalid table name: ' + table)
        if type(fields) is not dict:
            raise ValueError('Fields must be a dict')
        # Make / replace 'built-in' fields
        fields['id'] = 'text'
        fields['score'] = 'real'
        fields['timestamp'] = 'int'
        # Build the actual definitions
        table_def = ('CREATE TABLE ' + table + ' (' +
            ','.join(['\n    ' + self.__make_field_def(k, v) for k, v in fields.iteritems()] +
                ['\n    PRIMARY KEY (id)']
            ) + '\n)')
        return table_def

    def __make_field_def(self, field, ftype):
        _ = self
        if type(field) is not str:
            raise ValueError('Field name must be a string')
        if type(ftype) is not str:
            raise ValueError('Field type must be a string')
        # Validate field name + type
        if not re.match('^[A-Za-z][_a-zA-Z0-9]*$', field):
            raise ValueError('Invalid field name: ' + field)
        if ftype not in ('text', 'int', 'real', 'datetime', 'fulltext'):
            raise ValueError('Invalid type')
        # Handle fulltext specially
        if ftype == 'fulltext':
            ftype = 'int'
        # Return field def
        return field + ' ' + ftype

    def install(self, cur):
        logger.info("Installing schema: %s", self.setup_str)
        cur.executescript(self.setup_str)

    def uninstall(self, cur):
        logger.info("Unistalling schema: %s", self.delete_str)
        cur.executescript(self.delete_str)

    def delete_record(self, cur, hid):
        # TODO: Implement and attach
        pass

    def insert_record(self, cur, hid, summary, data, score):
        try:
            (ctype, body) = record.get_record_content(record.RT_WORKTOKEN, data)
            if ctype != 'application/json':
                raise ValueError('Not a json')
            # Decode it
            obj = json.loads(body)
            # TODO: Why is this pylint disable needed?
            # pylint: disable=no-member

            # Grab the table special variable and make sure it's in schema
            table_name = obj['_table']
            table = self.schema[table_name]
            del obj['_table']

            # Overwrite 'special' fields
            obj['id'] = str(hid).encode('base64')[:-1]
            obj['score'] = score
            obj['timestamp'] = struct.unpack("!LL", summary)[0]

            # Check values, remove extra fields
            for field, value in list(obj.iteritems()):
                if field not in table:
                    del obj[field]
                    continue
                if not re.match('^[A-Za-z][_a-zA-Z0-9]*$', field):
                    raise ValueError('Invalid field name: ' + field)
                if type(value) is dict or type(value) is list:
                    raise ValueError('Complex types not allowed for fields')

            # Make the statement
            stmt = ('INSERT INTO ' + table_name +
                ' (' + ','.join(obj.keys()) + ') VALUES (' +
                ','.join(['?'] * len(obj)) + ')')

            # Run it
            cur.execute(stmt, obj.values())
        except: # pylint: disable=bare-except
            logger.debug("%s", traceback.format_exc())
            # If it fails, no big...

