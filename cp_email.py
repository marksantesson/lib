
#Copyright 2014 Mark Santesson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# kr *.py -c "python cp_email.py -u"


'''
I wrote this so that I could email results from my irrigate
project. Later I made it so that I could run a program and
mail the results. I did that so that I could email the
results of the clamav antivirus scanner.

crontab -e:
    0 4 * * * (rm /tmp/scan ; ((clamscan -i -l /tmp/scan -z --exclude-dir="^/(dev|cdrom|media/cdrom|sys)" -r /)) ; chmod a+r /tmp/scan ; ( cd /home/usrofsvn/markets/Code/irrigate ; su -c "python ../lib/cp_email.py --ob run-and-send @password @password marksantesson@gmail.com cat /tmp/scan --subject='Antivirus'" usrofsvn))

The module supports more direct emailing, but I didn't want
to execute code as root that is held in a user directory
and easily changeable through git. The following should
work:
    0 4 * * * ( cd /home/usrofsvn/markets/Code/irrigate ; python ../lib/cp_email.py --ob run-and-send @password @password recipient@email.com clamscan -r / --subject="Antivirus run")






'''

__all__ = ('get_email,send_email,build_message,run_and_email_result'
           ',main'
          ).split(',')


import datetime
import logging
import mock
import email
import email.utils
import imaplib
from   pprint import pformat
import smtplib
import socket
import sys
import unittest
from   xml.etree.ElementTree import ElementTree as ET


def get_email(username, password, since_date=None, processFn=None):
    '''Returns a dict mapping message id to (response, message)
for the messages stored in a gmail account.
username should end in @gmail.com.
password can be a string or a callable that returns a
string.
since_date is one of None, a datetime.date, or a string in
DD-Mon-YYYY format.
The returned messages are inclusive of since_date.
If specified, processFn will be called for every
received message. It is passed two parameters: the
email id, and the message. The message is given in the form
of en email.message.Message object.
    '''
    # Recipe from:
    # http://stackoverflow.com/questions/348630/how-can-i-download-all-emails-with-attachments-from-gmail

    assert username.endswith('@gmail.com'), \
            'Must send through gmail: {}'.format(username)

    m = imaplib.IMAP4_SSL("imap.gmail.com")
    m.login(username, password() if callable(password) else password)
    m.select()
    resp,mailboxes = m.list()

    search_fields = ''
    if since_date is not None:
        if isinstance(since_date, datetime.date):
            since_date = since_date.strftime('%d-%b-%Y')
        search_fields = ( search_fields
                        + ( ' ' if search_fields else '' )
                        + 'SINCE "{0!s}"'.format(since_date)
                        )
    if not search_fields:
        search_fields = 'ALL'
    else:
        search_fields = '(' + search_fields + ')'
    try:
        resp, items = m.search(None, search_fields)
    except Exception:
        logging.exception('When trying: m.search(None, %r)', search_fields)
        raise
    items = items[0].split()

    msgs = dict()
    for emailid in items:
        resp, data = m.fetch(emailid, "(RFC822)")
        email_body = data[0][1]
        msg = email.message_from_string(email_body)
        msgs[emailid] = (resp,msg)

        if processFn:
            processFn(emailid, msg)

    return msgs



def send_email(username, password, recipients, message):
    '''Returns a dictionary of errors or an empty dict if all
recipients received the message okay.
username should end in @gmail.com.
password can be a string or a callable that returns a
string.
recipients should be a list of email addresses to receive
the message.
message should be a string. It can be constructed by
build_message.
    '''
    # I wish I could remember where I found this recipe...
    assert isinstance(message, basestring)

    assert username.endswith('@gmail.com'), \
            'Must send through gmail: {}'.format(username)
    try:
        session = smtplib.SMTP('smtp.gmail.com', 587)
        logging.debug( 'session =%r', session )
    except socket.gaierror, e:
        if 'getaddrinfo failed' not in repr(e):
            raise e

        logging.error( 'Encountered %r: probably not connected to the internet.', e )
        raise e

    # It uses encryption after starttls.
    x = session.starttls()
    logging.debug( 'session.starttls() =%r',x)

    logging.info(username)
    x = session.login(username, password() if callable(password) else password)
    logging.debug( 'session.login(%r, ...) = %r', username, x)

    res = session.sendmail(username, recipients, message)
    logging.debug( 'session.sendmail(%r, %r, %r ...) = %r'
                 , username, recipients, message[:80], res )

    x = session.quit()
    logging.debug( 'session.quit() = %r', x )

    return res


def build_message( username, recipients, subject, html_tree
                 , reply_to=None, attachments=[] ):
    '''Constructs a mime email from an ElementTree representing
an html message, and include relevant headers and
attachments. The returned value is the string
representation of the mime email.
username should end in @gmail.com.
recipients must be a list of strings.
subject is a string of the subject of the message.
html_tree must be a string or an ElementTree which will be
converted to a string.
reply_to, if present, will be used for the ReplyTo field.
attachments must be tuples of the filename and the data to
attach. Mime type will be inferred from the extension to
the filename. Attachments should be referenced in the html
like so:
    <img src="cid:NAME">
... where NAME does not need to be in caps and should not
have a file extension. The name given to this function
should have an extension.
'''

    assert isinstance(username, basestring)
    assert isinstance(recipients, list)
    assert isinstance(recipients[0], basestring)
    assert isinstance(subject, basestring)
    assert isinstance(html_tree, (basestring, ET))

    from email.MIMEMultipart import MIMEMultipart
    from email.MIMEImage     import MIMEImage
    from email.MIMEText      import MIMEText

    headers = [ 'From: {}'   .format( username )
              , 'Subject: {}'.format( subject )
              , 'To: {}'     .format( ';'.join(recipients) )
              , 'MIME-Version: 1.0'
              , 'Content-Type: text/html'
              ]
    if reply_to:
        headers.append('Reply-To: {}'.format( reply_to ))
    headers = '\r\n'.join(headers)

    message = MIMEMultipart()
    message['From'   ] = username
    message['To'     ] = ';'.join(recipients)
    message['Subject'] = subject

    for i,att in enumerate(attachments):
        if isinstance(att, MIMEImage):
            message.attach(att)
        else:
            name,data = att
            filename,ext = name.rsplit('.', 1)
            assert ext.lower() in 'png,jpg,gif,jpeg,bmp'.split(',')
            mimg = MIMEImage( _imagedata=img, _subtype=ext )
            mimg.add_header( 'Content-Disposition', 'attachment'
                           , filename=filename)
            mimg.add_header('Content-ID', '<{}>'.format(filename))
            message.attach(mimg)
        # Non images should be MimeAudio or MimeApplication, I think.

    html = html_tree.tostring() if isinstance(html_tree, ET) else html_tree
    body = MIMEText(html, 'html')
    message.attach( body )

    return message.as_string()


def run_and_email_result(username, password, recipients, msg, *args, **kwargs):
    '''Run a program and email the results.
username should end in @gmail.com.
password must be a string or a callable which returns a
string.
recipients must be a list of strings.
msg is the message to be sent. It should be a string. If
the value is falsy, then there is a standard template that
will be used. If provided, then the message will have
"format" called on it, with several parameters relevant to
how the program ran. "command" is the list of command line
arguments. "exitcode" is the exit code of the process.
"starttime" and "endtime" are datetimes. "runtime" is a
timedelta.

The remainder of the arguments are the name of the program
to run and the command line parameters to give to it, just
as if it had been invoked on the command line.
subject is optional and, if provided, is a string of the
subject to be placed on the message.

'''
    params = dict( starttime = datetime.datetime.now()
                 , command   = args
                 )
    subject = kwargs.pop('subject', '')
    assert not kwargs, 'Leftover kwargs: %r' % (kwargs,)
    msg = msg or '''\
<body>
    <h2>Execution results:</h2>
    <h3>Results of executing {command!r}</h3>
    <h3>Exit code: {exitcode}</h3>
    <h3>Start time: {starttime!s}</h3>
    <h3>End time: {endtime!s}</h3>
    <h3>Run time: {runtime!s}</h3>
    ========================================
<BR><pre>{results}</pre>
</body>
'''

    import subprocess
    try:
        output = subprocess.check_output( args
                                        , stderr=subprocess.STDOUT
                                        )
        exitcode = 0
    except subprocess.CalledProcessError as e:
        exitcode,output = e.returncode,e.output

    params['endtime']  = datetime.datetime.now()
    params['runtime']  = params['endtime']-params['starttime']
    params['exitcode'] = exitcode
    params['results']  = output

    try:
        msgtext = msg.format(**params)
        subject = subject.format(**params) if subject is not None else ''
        message = build_message( username, recipients, subject, msgtext )
    except KeyError, e:
        logging.error(('KeyError when formatting message. Message text:'
                       '\n%s\n\nAvailable params: %r'
                      ) % (msg, params.keys(),))
        raise
    res = send_email( username, password, recipients, message )
    return res


def run_tests():
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    unittest.TextTestRunner().run(suite)


class TestTesting(unittest.TestCase):
    def test_send_mail(self):
        session = mock.Mock(sendmail=mock.Mock(return_value={1:2}))
        with mock.patch('smtplib.SMTP', return_value=session):
            self.assertRaises( AssertionError, send_email
                             , 'not_gmail@example.com', 'spam'
                             , ['arthur@example.com','robin@example.com']
                             , '''<body>Test email message.</body>'''
                             )
            res = send_email( 'sample@gmail.com', 'spam'
                            , ['arthur@example.com','robin@example.com']
                            , '''<body>Test email message.</body>'''
                            )
            self.assertEquals(res, {1:2})
    def test_run_and_email_results(self):
        args = [ 'ls', ]
        session = mock.Mock(sendmail=mock.Mock(return_value={1:2}))
        with mock.patch('smtplib.SMTP', return_value=session):
            self.assertRaises( AssertionError, run_and_email_result
                             , 'not_gmail@example.com', 'spam'
                             , ['arthur@example.com']
                             , None
                             , *args
                             , subject = 'test subject'
                             )
            res = run_and_email_result( 'sample@gmail.com', 'spam'
                                      , ['arthur@example.com']
                                      , None
                                      , *args
                                      , subject = None
                                      )
            self.assertEquals(res, {1:2})
            self.assertEquals(1, len(session.sendmail.call_args_list))
            call = session.sendmail.call_args_list[0]
            frm,to,msg = call[-2]
            self.assertIn('Exit code', msg)
            # Capture what was sent in an email and verify it.

def main(*args):
    '''The main function can take the same arguments that can be
passed the same arguments that can be passed to the script
on the command line.
'''
    import argparse

    if not args:
        args = sys.argv

    def set_cmd_fn(x):
        def fn(opt, x=x):
            opt.command = x
        return fn

    descr = ''' cp_email - Functions to send email through a gmail account.
Also a command-line runnable script to perform email
related tasks.  cp_email supports a simplistic password
obfuscation method. If enabled, the password will have each
digit shifted to the previous ascii value. The password
"cat" should be passed to the program as "dbu". This is
obviously not intended to keep the password entirely safe,
but just to prevent it from being used by bots that might
get ahold of it. The password can be a string or a callable
that produces a string. The latter is recommended as it
will obscure the password value on a locals variable dump.
'''

    all = argparse.ArgumentParser(add_help=False)
    all.add_argument( '--loglevel', dest='loglevel'
                    , type=str, default='INFO'
                    , choices='CRITICAL,ERROR,WARNING,INFO,DEBUG'
                              .split(',')
                    , help='(default: %(default)s)'
                    )

    ### PARENT (sets up username and password)
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument( 'username', type=str
                       , help='The username to use to log into gmail.'
                              ' The username must be an @gmail.com'
                              ' address. If preceded by @, then the value'
                              ' indicates a filename. The first line of the'
                              ' file contents will be used for the username.'
                       )
    parent.add_argument( 'password', type=str
                       , help='The password, or, if preceded by @, the'
                              ' filename where the password is stored.'
                              ' If the file contains multiple lines, it'
                              ' will take the password from the last line.'
                       )
    parent.add_argument( '--ob', dest='obfuscated', default=False
                       , action='store_true'
                       , help='Enable elementary password obfuscation (ROT1)'
                       )

    parser = argparse.ArgumentParser( description=descr, parents=[all] )

    ### ACTUAL-SEND
    subparsers = parser.add_subparsers(dest='command')
    send_parser = subparsers.add_parser( 'actual-send', parents=[all,parent]
                                       , help='Test actually sending an email.'
                                       )

    ### ACTUAL-RECEIVE
    recv_parser = subparsers.add_parser( 'actual-receive', parents=[all,parent]
                                       , help='Test receiving emails.'
                                       )

    ### RUN-AND-SEND
    runs_parser = subparsers.add_parser( 'run-and-send', parents=[all,parent]
                                       , help='Run command and email results.')
    runs_parser.add_argument( 'recipients', type=str
                            , help='Comma separated list of emails to'
                                   ' receive email. (Specify "-" for the'
                                   ' sending username.)'
                            )
    runs_parser.add_argument( '--subject', dest='subject', type=str
                            , help='The subject for the email.'
                            )
    runs_parser.add_argument( 'args', type=str, nargs='+'
                            , help='The remaining arguments are the command'
                                   ' to run.'
                            )

    ### TEST
    test_parser = subparsers.add_parser( 'test', parents=[all]
                                       , help='Run unit tests.' )

    options = parser.parse_args()

    if 'loglevel' in options:
        logging.getLogger().setLevel(getattr(logging, options.loglevel))

    if options.command == 'test':
        run_tests()
    else:
        if options.username.startswith('@'):
            options.username = open(options.username[1:]).readlines()[0].strip()

        if options.password.startswith('@'):
            options.password = lambda fname=options.password[1:]: \
                                      open(fname).read().strip()\
                                          .split('\n')[-1].strip()
        else:
            options.password = lambda pw=options.password: pw

        if options.obfuscated:
            options.password = lambda pw=options.password(): \
                                      ''.join([ chr(ord(x)-1) for x in pw ])

        logging.info(options)

        if options.command == 'actual-send':
            # This actually send an email if connected to gmail.
            message = build_message( options.username, [options.username]
                                   , 'Test email'
                                   , '''<body>Test email body.</body>''')
            send_email( options.username, options.password()
                      , [options.username], message)
        elif options.command == 'actual-receive':
            # This actually receives emails if connected to gmail.
            a_week_ago = datetime.date.today() - datetime.timedelta(days=7)
            ret = get_email(options.username, options.password(), a_week_ago)
            print ret
            return ret

        elif options.command == 'run-and-send':
            if options.recipients != '-':
                options.recipients = options.recipients.split(',')
            else:
                options.recipients = [ options.username, ]
            run_and_email_result( options.username, options.password
                                , options.recipients
                                , None, *options.args, subject=options.subject)
        else:
            raise Exception('Unexpected command: %s', options.command)


if __name__ == '__main__':
    main()

