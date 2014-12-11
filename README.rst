Riak CS CLI helper
=============================

This command line tool helps your Riak CS life.
`s3cmd <http://s3tools.org/s3cmd>`_ is an excellent tool to operate S3 compatible storage services.
But Riak CS has additional features (like user account management). This tool completes that area.

Install
-------------

.. code-block:: bash

   $ go get github.com/shibukawa/riakcs-helper

Usage
-------------

Config
~~~~~~~

.. code-block:: bash

   $ riakcs-helper init [host] [adminAccessKey] [adminSecretKey] [*proxy*]

Riak CS assumes using sub-domain for bucket name. But this is a little difficult for testing server.
In this case, you should set **host** and **proxy**.

**host** should be a value specified in `/etc/riak/app.config` (default value is `s3.amazonaws.com`).
**host** doens't have schema (`http://`) and this tool doesn't support https now.

**proxy** is an optional parameter and should be an actual reachable IP address. It needs schema `http://`.

Before running this command, you should create administrator account.

**SAMPLE:**

.. code-block:: bash

   $ riakcs-helper init s3.amazonaws.com -LG_3TE1KSSKPY-C7GPD 4_rwEo4HwX-Wi2eEIUrg5oh7nF5mNMx9-pKI2g== http://127.0.0.1:8080

   setting file /Users/shibukawa/.riakcs_helper is written.

Create User
~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper create-user [userName] [email]

Create user account.

**SAMPLE:**

.. code-block:: bash

   $ riakcs-helper create-user shibukawa yoshiki@shibu.jp

   Create user successuflly
     name:         shibukawa
     display-name: yoshiki
     email:        yoshiki@shibu.jp
     id:           d2b5347521fdd3d9fd1a097a8b996e74dcd0bb5d4f0c9e3bf63a217af56a9810
     access-key:   6FICT_FBEXFO3NEHLSSQ
     secret-key:   e1x7WXmpio4ZDtqA49aO8dJSltKIKDos8pFNIA==
     status:       enabled

Create User
~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper modify-user [oldName] [newUserName] [newEmail]

Modify user name and email address. **oldName** should be human-readable `name`. Neither `display-name` nor `id`, `access-key` etc.

Show User(s)
~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper show-user [*userName*]

Show user information registered in Riak CS. If you pass optional **userName** parameter, this command shows only that user.

Reset Secret Key
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper issue-credential [userName]

Enable User
~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper enable-user [userName]

Disable User
~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper disable-user [userName]

Create New Bucket
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper create-bucket [bucketName] [*accesibleUserName*]

Create bucket. If user **accesibleUserName** is passed, this command gives read/write access to the user.

.. code-block:: bash

   $ riakcs-helper create-bucket [bucketName] [*accesibleUserName*]
   Create bucket 'test12' successuflly

Delete Bucket
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper delete-bucket [*-f*] [bucketName]

Detele specified bucket. **-f** option is used, it removes all content and and bucket at the same time.
Otherwise, delete operation will be failed if there are any content in the bucket.

Clean Bucket
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper clean-bucket [bucketName]

This command removes all content of specified bucket.

List Bucket/Contents
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper list [*bucketName*]

If **bucketName** is omitted, this command shows bucket list. Otherwise, it shows contents of the bucket.

Set ACL (simple)
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper set-acl [bucketName] [accesibleUserName]

Gives read/write access to specified user (owner is admin).

* Administrator: `FULL_CONTROL`
* Specified User: `READ/WRITE`

If you need more detailed ACL, use `x3cmd`.

Create Bucket and User (both have same name)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ riakcs-helper create-project [bucketAndUserName] [email]

Create user and bucket (both have same name).
New user has READ/WRITE access of the new bucket.
Internally, this command calls the following three commands:

* Create bucket
* Create user
* Set new bucket's ACL for the new user

**SAMPLE:**

.. code-block:: bash

   $ riakcs-helper create-project awesome-images awesome-images@example.com

   Create bucket 'awesome-images' successuflly
   Create user successuflly
     name:         awesome-images
     display-name: awesome-images
     email:        awesome-images@example.com
     id:           7b6d4d28d5b58920bcb3fee2e22b4e19c1c8a46c5607aabb8953cbbe13d1c5ec
     access-key:   -LG_3TE1KSSKPY-C7GPD
     secret-key:   4_rwEo4HwX-Wi2eEIUrg5oh7nF5mNMx9-pKI2g==
     status:       enabled
   Set bucket test12's ACL successfully.
	   owner: admin (FULL_CONTROL)
	   user : awesome-images (READ/WRITE)

License
--------

Apache v2. See `LICENSE.rst`.
