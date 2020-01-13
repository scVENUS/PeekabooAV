=======
Ruleset
=======

This chapter explains how to use and take care of the ruleset. We assume you
have peekaboo up and running and want to tweak or understand the default
ruleset.

We also asume you are familiar with python config parser.

Section: rules
==============

Here rules can be disabled by putting a ``#`` (comment) in front. Also the
order in which the rules will be processed can be changed by changing how
the rules are listed (note that the trailing number is not relevant).

Following sections
==================

The following sections are processed (if enabled in rules section) and
contain for example the whitelist mime types. Individual entries within
for example the whitelist can be disabled by putting an ``#`` in front.

Expressions
===========

* rule : a rule of the ruleset, e.g. evil_sig or expression
* expression : an expression of the expression rule
* condition : the condition before ``->``

Expressions will be tried one after another until one matches. The general
structure of an expression is: ``<condition> -> <result>``. If condition
evaluates to true, the expression will be considered matching and result will
be returned by the rule.

Possible results are: ``unknown``, ``ignore``, ``good`` and ``bad``. The
latter three will terminate ruleset processing and use the result as final
analysis result while the former will continue on with the next rule of the
ruleset.

It is a lot like Python itself.

They can contain operators:
``+ - * ** / // % << >> . < <= > >= == != in not in is is not isdisjoint and or``

Datatypes are:
``boolean, integer, real, string, regex, identifier, result``

Rules can then be constructed like:

.. code-block:: shell

    expression.1  : sample.mimetypes <= {'text/plain', 'inode/x-empty', 'image/jpeg'} -> ignore
    expression.2  : sample.meta_info_name_declared == 'smime.p7s'
                        and sample.meta_info_type_declared in {
                            'application/pkcs7-signature',
                            'application/x-pkcs7-signature',
                            'application/pkcs7-mime',
                            'application/x-pkcs7-mime'
                        } -> ignore
    expression.3  : /DDE/ in cuckooreport.signature_descriptions -> bad
    expression.4  : /suspicious/ in olereport.vba_code -> bad
    expression.5  : olereport.has_office_macros == True
                        and cuckooreport.score > 4 -> bad
    expression.6  : sample.file_extension in {"doc", "docx"}
                        and /.*\/rtf/ in {sample.declared_mimetype}|filereport.mime_types -> bad
    expression.7  : sample.file_extension in {"doc", "docx"}
                        and not filereport.type_by_content in { /application\/.*word/ } -> bad
    expression.8  : filereport.type_as_text == "AppleDouble encoded Macintosh file" -> ignore
    expression.9  : {sample.declared_mimetype}|filereport.mime_types <= {
                        and /.*\/(rtf|richtext)/ in ({sample.declared_mimetype} | filereport.mime_types) -> bad

Attributes of sample
--------------------

.. code-block:: shell

    filename
    sha256sum
    name_declared
    file_extension
    mimetypes
    file_size
    meta_info_name_declared
    meta_info_type_declared

Attributes of cuckooreport
--------------------------

.. code-block:: shell

    requested_domains
    signatures
    signature_descriptions
    score
    errors
    cuckoo_server_messages

Attributes of olereport
-----------------------

.. code-block:: shell

    has_office_macro
    vba_code

Attribuges of filereport
------------------------

.. code-block:: shell

    type_by_content
    type_by_name
    type_as_text
