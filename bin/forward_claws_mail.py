#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# scan_emailed_file.py                                                        #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2018  science + computing ag                             #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or (at       #
# your option) any later version.                                             #
#                                                                             #
# This program is distributed in the hope that it will be useful, but         #
# WITHOUT ANY WARRANTY; without even the implied warranty of                  #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU           #
# General Public License for more details.                                    #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################


"""
Use with
    claws Mail. Add an new Action (Shell command): python /path/to/script.py %f
    or run add as argument the path of a full email file.
"""


from __future__ import  print_function
import os
import sys
import pwd
import socket
import smtplib
import email
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate


def send_mail(send_from, send_to , msg,server="127.0.0.1", port="25"):
    """
    Send an email.

    :param send_from: Email sender
    :param send_to: The recipient
    :param msg: The full message which will be forwarded
    :param server: FQDN or IP of the mail server
    :param port: TCP port of the mail server
    """

    smtp_client = smtplib.SMTP(server, port)
    msg.replace_header('from', send_from)
    msg.replace_header('to', COMMASPACE.join(send_to))
    smtp_client.sendmail(send_from, send_to, msg.as_string())
    smtp_client.close()


def main():
    user = pwd.getpwuid(os.getuid()).pw_name
    host = socket.gethostname()
    # open the file
    path=sys.argv[1]
    with open(path,'r') as file:
        msg=email.message_from_file(file)


    send_mail("%s@%s" % (user, host), ["scan@peekaboohost"],msg, "localhost", 10024)


if __name__ == '__main__':
    main()
