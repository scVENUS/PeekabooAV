#!/bin/bash

echo 'Peekaboo development mail server is listening on localhost:10025'

python -m smtpd -n -c DebuggingServer localhost:10025
