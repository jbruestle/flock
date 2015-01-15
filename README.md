
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
TODO

developing flock
================
TODO

