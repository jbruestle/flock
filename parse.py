#!/usr/bin/python

import hashlib
import sqlite3
import simplejson as json
import re
import base64

class store:
    internal_sql = '''
    CREATE TABLE _record (
        id       text,
        record   text,
        wt_seq   int,
        wt_time  int,
        wt_nonce text,
        wt_score real,
        PRIMARY KEY (id)
    );
    CREATE INDEX _record_wt_score ON _record (wt_score);
    CREATE INDEX _record_wt_seq ON _record (wt_seq);
    '''
    def __init__(self, db_json):
        self.con = sqlite3.connect(":memory:")
        self.cur = self.con.cursor()
        self.seq = 1
        obj = json.loads(db_json)
        if type(obj) is not dict:
            raise ValueError('DB defintion must be an object')
        if 'schema' not in obj:
            raise ValueError('DB missing schema')
        self.schema = obj['schema']
        setup_str = store.internal_sql
        setup_str += self.make_schema()
        if 'indexes' in obj:
            setup_str += self.make_indexes(obj['indexes'])
        #print setup_str 
        self.cur.executescript(setup_str)
        if 'queries' in obj:
            # TODO: Better error message on bad type in queries
            qsrc = obj['queries']
            self.queries = {k : ' '.join(v) for k,v in qsrc.iteritems()}

    def make_schema(self):
        # Iterate over each table and make SQL to construct it
        if type(self.schema) is not dict:
            raise ValueError('Schema defintion must be an object')
        schema_str = ''
        for table, fields in self.schema.iteritems():
            schema_str += self.make_table_def(table, fields) + ';\n'
        return schema_str

    def make_indexes(self, indexes):
        if type(indexes) is not list:
            raise ValueError('Index defintions must be a list')
        # Iterate over each index and make SQL to construct it
        indexes_str = ''
        for idx in indexes:
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

    def make_table_def(self, table, fields):
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
            ','.join(['\n    ' + self.make_field_def(k,v) for k,v in fields.iteritems()] +
                ['\n    PRIMARY KEY (id)']
            ) + '\n)')
        return table_def
       
    def make_field_def(self, field, ftype):
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
    
    def insert_record(self, json_str, wt_time, wt_nonce):
        # Generate hash
        jhash = base64.urlsafe_b64encode(hashlib.sha224(json_str).digest())

        # Insert into the 'internal' table
        self.cur.execute(
            "INSERT INTO _record " + 
            "(id, record, wt_seq, wt_time, wt_nonce, wt_score)" +
            "VALUES ($id, $record, $seq, $wt_time, $wt_nonce, $wt_score)", { 
                "id" : jhash, 
                "record" : json_str, 
                "seq" : self.seq,
                "wt_time" : wt_time, 
                "wt_nonce" : wt_nonce,
                "wt_score" : 0.0
            })

        # Move local sequence forward
        self.seq += 1

        error = None
        try:
            self.expand_record(jhash, json_str)
        except Exception as e:
            error = str(e)

        return (jhash, error)

    def update_wt(self, jhash, wt_time, wt_nonce):
        # Insert into the 'internal' table
        self.cur.execute(
            "UPDATE _record " +
            "SET wt_seq = $seq, wt_time = $wt_time, wt_nonce = $wt_nonce, wt_score = $wt_score " +
            "WHERE id = $id AND wt_score < $wt_score", {
                "id" : jhash, 
                "seq" : self.seq,
                "wt_time" : wt_time, 
                "wt_nonce" : wt_nonce,
                "wt_score" : 0.0
            })

        # Move local sequence forward
        self.seq += 1

    def get_updates(self, since, count):
        self.cur.execute(
            "SELECT wt_seq, id, wt_time, wt_nonce " +
            "FROM _record " +
            "WHERE wt_seq > ? " +
            "LIMIT ?",
            (since, count))
        rows = self.cur.fetchall()
        return json.dumps(rows)

    def expand_record(self, jhash, json_str):
        # Try to decode, if it's not json, forget it
        obj = json.loads(json_str)

        # Grab the table special variable and remove
        table = obj['_table']
        if not re.match('^[A-Za-z][_a-zA-Z0-9]*$', table):
            raise ValueError('Invalid table name: ' + table)
        del obj['_table']

        # Make sure json doesn't have 'id' special field, and add
        if 'id' in obj:
            raise ValueError('Id cannot be specified')
        obj['id'] = unicode(jhash)

        # Check values
        for field, value in obj.iteritems():
            if not re.match('^[A-Za-z][_a-zA-Z0-9]*$', field):
                raise ValueError('Invalid field name: ' + field)
            if type(value) is dict or type(value) is list:
                raise ValueError('Complex types not allowed for fields')

        # Make the statement
        stmt = ('INSERT INTO ' + table +
            ' (' + ','.join(obj.keys()) + ') VALUES (' +
            ','.join(['?'] * len(obj)) + ')')

        # Run it
        self.cur.execute(stmt, obj.values())
        return jhash

    def run_query(self, name, params):
        # TODO: read only, timeout, etc
        self.cur.execute(self.queries[name], params)
        print self.cur.fetchone()


with open('db.json', 'r') as f:
    db_json = f.read()
#print db_json
s = store(db_json)
uid, e1 = s.insert_record(json.dumps({
    '_table' : 'user',
    'handle' : 'melvin',
    'pub_key' : 'xxx'
}), 1000, "hello") 
pid, e2 = s.insert_record(json.dumps({
    '_table' : 'post',
    'user_id' : uid, 
    'title' : 'This is a test post',
    'text' : 'Hey man, like I said, it''s a test post, so leave me alone',
}), 1010, "what")
s.run_query("lame_posts", {})
print s.get_updates(0, 50)

#cur.executescript(schema)
#test_val = '{"_table": "test", "hello": "world", "num": 15.1}' 
#send_to_db(cur, test_val)
#cur.execute("SELECT * from test");
#print cur.fetchone()

