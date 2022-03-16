#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# scan_emailed_file.py                                                        #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2022 science + computing ag                              #
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
Use with::
    python -m smtpd -n -c DebuggingServer localhost:10025

as mailserver or use the script "run_dev_mailserver.sh".
"""


import os
import sys
import pwd
import socket
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate


def send_mail(send_from, send_to, subject, text, files=[],
              server="127.0.0.1", port="25"):
    """
    Send an email.

    @param send_from: Email sender
    @param send_to: The recipient
    @param subject: Email subject
    @param text: Email content
    @param files: A list of files to attach to the mail
    @param server: FQDN or IP of the mail server
    @param port: TCP port of the mail server
    """
    assert isinstance(send_to, list)

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    for f in files:
        # triggers encoding as per RFC2231
        filename_tuple = ('utf-8', '', os.path.basename(f))
        with open(f, "rb") as fil:
            part = MIMEApplication(fil.read(), Name=filename_tuple)

        # After the file is closed
        part.add_header(
            'Content-Disposition', 'attachment', filename=filename_tuple)
        msg.attach(part)

    smtp_client = smtplib.SMTP(server, port)
    smtp_client.sendmail(send_from, send_to, msg.as_string())
    smtp_client.close()


def main():
    user = pwd.getpwuid(os.getuid()).pw_name
    host = socket.gethostname()

    if len(sys.argv) < 2:
        # Not enough arguments
        print('Usage: %s file1 file2 ... fileX' % __file__)

    send_mail("%s@%s" % (user, host), ["scan@peekaboohost"],
              "Check this for me pls",
              "Are the attached files malicious?",
              sys.argv[1:], "localhost", 10024)


if __name__ == '__main__':
    main()
