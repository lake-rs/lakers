=======================================================
lakers -- An implementation of EDHOC (RFC 9528) in Rust
=======================================================

This is the documentation of the Python bindings for Lakers,
called lakers-python_.
Documentation on the underlying Rust library is found `on docs.rs`_.

See the project README_ file for installation, maintenance and license information.

.. _README: https://github.com/lake-rs/lakers/blob/main/lakers-python/README.md
.. _lakers-python: https://pypi.org/project/lakers-python/
.. _`on docs.rs`: https://docs.rs/lakers/

.. toctree::
   :hidden:

   API documentation <self>
   CHANGELOG.md

API documentation
=================

.. automodule:: lakers
   :members:
   :undoc-members:
   :exclude-members: EdhocInitiator, EdhocResponder

   These are the two main entry points:

   .. autoclass:: EdhocInitiator
     :exclude-members: prepare_message_1, parse_message_2, verify_message_2, prepare_message_3, completed_without_message_4, process_message_4
     :members:
     :undoc-members:

     .. automethod:: prepare_message_1
     .. automethod:: parse_message_2
     .. automethod:: verify_message_2
     .. automethod:: prepare_message_3
     .. automethod:: completed_without_message_4
     .. automethod:: process_message_4

   .. autoclass:: EdhocResponder
     :members:
     :exclude-members: process_message_1, prepare_message_2, parse_message_3, verify_message_3, completed_without_message_4, prepare_message_4
     :undoc-members:

     .. automethod:: process_message_1
     .. automethod:: prepare_message_2
     .. automethod:: parse_message_3
     .. automethod:: verify_message_3
     .. automethod:: completed_without_message_4
     .. automethod:: prepare_message_4

   Several tool classes augment the operation of those classes:
