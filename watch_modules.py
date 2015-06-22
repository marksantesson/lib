#!python

#Copyright 2015 Mark Santesson
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


# Test with: kr.py *.py -c watch_modules.py


import os
import re
import sys


class ImportedModulesTimestampChecker(object):
    '''
       A class to help detect when one of the source files for a
    running process has changed.
       The returned object should be called periodically to let it check
    the timestamps of all files. There is, as of yet, no multi-threaded
    version.
       Typical use of this module would be to have it track the files
    being actively developed and to call a function resulting in program
    exit (perhaps sys.exit) when a change is detected. This works well
    when combined with "kr" to relaunch the program.

    '''
    def __init__(self, on_difference_fn, filename_filter_fn=None):
        '''
        Takes two parameters:
          on_difference_fn: a function taking the name of the file which
                      changed, which is called when the change is
                      detected.
          filename_filter_fn: a function taking a module's filename and
                      which should return True if the file's timestamp
                      should be observed. If the filename filter is a
                      string, then any filenames containing that string
                      will be observed. If not present, then all modules
                      will be tracked.
        '''
        self._onDifferenceFn = on_difference_fn

        if isinstance(filename_filter_fn, basestring):
            filename_filter_fn = lambda x: filename_filter_fn in x
        self._filenameFilterFn = filename_filter_fn or (lambda x:True)

        self._timestamps = {}

    def __call__(self):
        '''
        Call this periodically to do a check of the timestamps.
        '''
        # Get the timestamps on all matching files in this module's
        # directory. If any have changed, quit.
        all_files = [ x.__file__ for x in sys.modules.values()
                      if isinstance(x,type(sys))
                         and hasattr(x, '__file__')
                         and self._filenameFilterFn(x.__file__)
                    ]
        for module_name in sorted(all_files):
            module_name = re.sub(r'\.pyc$', r'.py', module_name)
            try:
                ts = os.stat(module_name).st_mtime
            except WindowsError:    # TODO: What is the error on Linux?
                logging.exception(module_name)
                pass
            else:
                if ts > self._timestamps.setdefault(module_name, ts):
                    self._onDifferenceFn(module_name)
                    self._timestamps[module_name] = ts


def main():
    import os.path
    import SocketServer
    import logging
    # From an example in the documentation for SocketServer.
    class TinyHandler(SocketServer.StreamRequestHandler):
        def handle(self):
            # Get one line.
            self.data = self.rfile.readline().strip()
            logging.info('Received: %r', self.data)
            out = self.data.lower()
            self.wfile.write(out)
            logging.info('Sending : %r', out)

    class TinySocketServer(SocketServer.TCPServer):
        def __init__(self):
            self._address = ("localhost", 9999)
            SocketServer.TCPServer.__init__( self
                                           , self._address
                                           , TinyHandler )
            self.timeout = 0.5
            self.quit = False
            self._timestampChecker = ImportedModulesTimestampChecker\
                    ( self.on_module_modification
                    , self.module_name_filter
                    )

        @staticmethod
        def module_name_filter(module_name):
            this_mod_name = os.path.basename(__file__).split('.')[0]
            return this_mod_name in module_name

        def on_module_modification(self, module_name):
            logging.info('Module %s was modified, exiting.', module_name)
            self.quit = True

        def run(self):
            logging.info('Listening at: %s', self._address)
            while not self.quit:
                self._timestampChecker()
                self.handle_request()
            logging.info('Quitting.')

    logging.getLogger().setLevel(20)
    tws = TinySocketServer()
    tws.run()

if __name__ == "__main__":
    main()

