
What is flock
=============

Flock is a distributed app synchronization system.  It lets you build web applications that don't need any web servers.  Each user's computer works as part of the application.  The goal of flock is to make more web sites distributed, which means less central control.

Is flock ready to use?
----------------------
Right now, flock is ready for developers, and savy command line users.  We plan to make installers for OS X, Windows to make the process easier in the near future.  In addition, we are still pre-1.0, so there may be compatibility breaking changes coming still.

How do I install it?
--------------------
For app developers and users, run:

```
pip install flocksync
```

If you want to develop the flock protocol/engine itself, see the 'developing flock' section.

How do I run it?
----------------
First, start by launching the flock service:

```
flock -d <storage_dir>
```

`<storage_dir>` is a path to where flock should store files that are part of the various apps your use or create.  

Once that is done, you need to join one or more 'apps'.  If you want to develp a new app, see the 'developing apps' section.  To join an app, you need to know the app's ID number.  Right now, the author is running a 'test-app' with the ID of `5a6961ca9a2d774b2a53e7f4b93d285cba586ac3`.  We plan to make a web interface for finding and joining new apps built in to flock, but for now, you need to use curl.

To join an app run:

```
curl -v -X POST --header "Content-Type: application/json" localhost:8000/<ID>/join_app -d '{}'
```

Where `<ID>` is replaced by the ID of the app, for example:

```
curl -v -X POST --header "Content-Type: application/json" localhost:8000/5a6961ca9a2d774b2a53e7f4b93d285cba586ac3/join_app -d '{}'
```

Yes, that's really ugly, don't worry, we'll fix it soon.  Once you've joined an app, you go to it by opening a browser and going to:

```
http://localhost:8000/<ID>/index.html
```

Where `<ID>` is replaced by the ID of the app again.  Right now, we don't automatically redirect to index.html, you have to have that.

developing apps
===============
[TODO: Describe which type of *apps* are appropriate]

While you read this, please feel free to take a peek at the example app, including in the `example` directory in the flock source.

First, you need to create a new app, which is just a POST:

```
curl -v -X POST --header "Content-Type: application/json" localhost:8000/create_app -d '{}'
```

This curl will return JSON with the newly created app id.

At this point you can 'PUT' and 'DELETE' and static content of your site, for example:

```
curl -v -X PUT --header "Content-Type: text/html" localhost:8000/<ID>/index.html --data-binary @index.html
```

Since this is a bit annoying, see the 'example' app included in flock source for an example of some shell scripts to make it a bit easier.  In the near term, we will be adding a bulk copy feature (or finding some existing tool).  One thing to note: the content type used in the PUT is the content type a user will get when they do a GET of the content.

If all you want is a static site, you are done.  Any user can just join your app, and the content will be synced to them.  As long as at least one machine is up (including your machine, or any users machine) new users can get the latest data.  And if you make any changes to content, they will automatically sync to the rest of the network next time you are online.  It's worth noting that changes are generally synced 'in-order', however only the newest version of any piece of content will be synced.  Also note, there is a limit to the total size of content, which is typically set to around 100 MB, and individual files are typically limited to 10 MB, so don't try to upload your movie collection.

However, a site with only static content is not very interesting, so let's talk about dynamic content.

In the flock model, most of the application logic lives client side, but the flock backend performs the important job of syncing, retaining, and allowing search of user 'records'.  Here's how it works: 

1) Any user can 'POST' a record, which is just a JSON object.  Generally, you application will do this via an AJAX call for the user.

2) These records are synced with everyone.  To prevent spamming, we use a work-token based system (described in protocol details).

3) Based on a 'schema' defined by the application owner, these records are placed into a sqlite3 database on each user's machine, which can contain whatever indexes are needed

4) The application can then run arbitrary read-only queries on the resulting database via an AJAX call.

Specifically, there are only 2 POST calls needed to do record storage and retrieval, along with the standard PUT method for writing static content, including the special schema file, `_schema`

Schema
------

Let's talk about the schema first.  The schema translates JSON record objects into database rows.  If a row is posted that doesn't match the schema, it will still be synced, but just not end up in the database.  In general, the true data is the JSON form, the schema maps this onto the database form, but the synchronization and storage layer doesn't care about the schema.  This means it's possible to update the schema and retain existing data, which will just be remapped if it matches the schema.  This allows sensible updates.

The schema defines a set of tables, and for each table, a set of columns.  Now, while we use databases to allow easy indexing and quering, please realize that the database here is really just that, a method for indexing and quering.  Due to the nature of the sync layer, things like unique indexes, foreign keys, etc, won't work, so don't get too attached to SQL concepts.

At any rate, the schema is simply a JSON object, consisting of two entries, 'schema', which defines the tables, and 'indexes', which defines the indexes.  Each table is in turn a JSON object consting of fields, which are just 'types' (int, text, etc).  The indexes are just a list of indexes, and for each index, the table followed by the fields to be indexed (note two indexes means two entries, a single entry with multiple fields will make a compound index).

Without further ado, here is a simple example:

```
{
    "schema" : {
        "user" : {
            "handle" : "text",
            "pub_key" : "text"
        },
        "post" : {
            "user_id" : "text",
            "link" : "text",
            "title" : "fulltext",
            "text" : "fulltext",
            "signature" : "text"
        },
        "comment" : {
            "parent_id" : "text",
            "user_id" : "text",
            "text" : "fulltext"
            "signature" : "text"
        }
    },
    "indexes" : [
        ["user", "handle"],
        ["post", "timestamp"],
	["comment", "parent_id"],
        ["post", "score"],
        ["user", "score"],
    ],
}
```

First, note that every table has three 'implicit' fields, which are:

`id text`: A unique text field (the base64 of a SHA256) for each 'record' added
`timestamp int` : When the record was added or 'upvoted' last.
`score real` : The score of this record (a function of newness + upvotes)

These don't appear in the table definition, but are part of the table.  

Second, types can only be `int`, `real` (or float), `text`, or `fulltext`.  The difference between `text` and `fulltext` determines if the sqlite3 full text indexing magic is applied.  This also complicates the queries, which will be explained below.

TODO: Explain full-text, generally, write some more about schemas

Adding data
-----------

To POST a record, send a POST to `localhost:8000/<ID>/add_record`, or from the applicaiton local perspective, just `add_record`.  This POST must have content type of `application/json`.  Generally, the records will be JSON objects.  One of the fields is '_table', which determines which of the tables in schema the records will be put into.  The remaining fields are the columns (not including the 'implicit' columns.  For example:

```
{    "_table" : comment, 
    "parent_id" : "0afavnb2Avsdfa<etc>...==",
    "user_id" : "0HACxksfa0as<etc>...==",
    "text" : "I really liked your post and would like to be your friend forever",
    "signature" : "<magic public key goo"
}
```

The return of an add_record post will be:
```
{  "success" : true, "id" : "Ab053xga<etc>..==" }

where the id is of course the ID of the newly generate record. This data will now be synced with everyone, and entered into the database.  Note, if there is a mismatch between the fields of the record and schema, the following with happen:

1) If _table doesn't exist, record will simply not appear in the database (although it will be still be synched)
2) If some of the fields don't exist in the schema, they will be ignored when entering them into the DB
3) If some fields from the DB are missing, they will be given 'default' values.

Querying data
-------------

To do a query, simply POST to `localhost:8000/<ID>/query`, or from the applicaiton local perspective, just 'query'. Once again, the content type must be 'application/json'.  The query, has two fields, 'query', which is a sql query, possible with some parameters, and 'params', which is either a list or object with the values for the parameters.  For example:

```
{
    "query" : "SELECT id, score FROM users where HANDLE = ?",
    "params" : ["melvin"]
}
```

This will return a list of rows, each a list of columns, such as:
```
{
    success : true,
    results : [["Hs0zxf0<etc>...", 1023.17] ["0HACxksfa0as<etc>...", 20.17]]
}
```

If the query failed, generally a 500 status is returned and the error is in the message.


Developing Flock
================

First, make sure to remove any pip installations of flock.  It's very easy to accidentally load the 'system' versions of the library during development, resulting in much confusion.  Second, check stuff out from github.  Finally, since flock is made to be packaged for installation/pip, to run it directly from a development environment use:

```
PYTHONPATH=`pwd` ./scripts/flock -d <storage_path>
```

To run the unit test for a given module in flock, for example, sync, do:

```
PYTHONPATH=`pwd` ./flock/sync
```

Also note: try to make your code pass pylint

Protocol Details
================
TODO



