

from twisted.internet import reactor
from peekaboo.toolbox.cuckoo import CuckooServer


class Cuckoo:
    def __init__(self):
        pass

    def submit(self):
        pass

    def do(self):
        # wait for the cows to come home
        while True:
            sleep(600)


class CuckooEmbed(Cuckoo):
    def __init__(self, interpreter, cuckoo_exec):
        self.interpreter = interpreter
        self.cuckoo_exec = cuckoo_exec

    def submit(self):
        # submit via call to submit
        pass

    def do(self):
        # reaktor and shit
        # Run Cuckoo sandbox, parse log output, and report back of Peekaboo.
        srv = CuckooServer()
        reactor.spawnProcess(srv, self.interpreter, [self.interpreter, '-u',
                                                       self.cuckoo_exec])
        reactor.run()


class CuckooApi(Cuckoo):
    def __init__(self, url):
        self.url = url


    def submit(self):
        pass

    def do(self):
        # do the polling for finished jobs
