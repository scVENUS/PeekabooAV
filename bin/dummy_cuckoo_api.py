#!/usr/bin/env python
""" Dummy Cuckoo API

to be used while developing PeekabooAV
Allows testing the API link to Cuckoo Sandbox

# requires
# pip install flask flask-restful """

import json
import random
import sys
import flask
import flask_restful


class Queue():
    """ Internal data structure to keep track of submitted tasks """
    def __init__(self):
        self.nextid = 1
        self.jobs = []

    def register_job(self):
        """ Adds a new job to the Queue and returns its id """
        self.nextid = self.nextid + 1
        self.jobs.append(self.nextid - 1)
        print("New job created %d. Queue %s" % (self.nextid-1, self.jobs))
        return self.nextid - 1

    def delete_job(self, job_id):
        """ Removes a job from the Queue """
        self.jobs.remove(job_id)
        print("Remove job {}. Queue %s".format(job_id) % self.jobs)


class QueueResource(flask_restful.Resource):
    """ Intermediate class to extend normal Resource by Queue """
    def __init__(self, queue):
        self.queue = queue


class Status(QueueResource):
    """ Resource to get Dummy Cuckoo's status on tasks """
    def get(self):
        """ Returns number of tasks in the respective state """
        result = {
            'tasks': {
                'reported': self.queue.nextid - 1 - len(self.queue.jobs),
                'running': len(self.queue.jobs),
                'total': self.queue.nextid - 1,
                'dummyAPIqueue': self.queue.jobs,
            }
        }
        return flask.jsonify(result)


class View(QueueResource):
    """ Resource to access state of task """
    def get(self, job_id):
        """ Returns the current status of a given job_id.
        Jobs finish by asking its state with a probability of 1/3 """
        job_id = int(job_id)

        # job doesn't exist
        if job_id >= self.queue.nextid:
            print("Job_id {} not found".format(job_id))
            flask_restful.abort(404,
                                message="Job_id %d doesn't exist" % job_id)

        running = job_id in self.queue.jobs
        finished = random.randint(0, 2) != 0
        if running and not finished:
            print("Job_id %d running" % job_id)
            return flask.jsonify({'task': {'status': 'running'}})

        if running:
            self.queue.delete_job(job_id)

        print("Job_id {} reported".format(job_id))
        return flask.jsonify({'task': {'status': 'reported'}})


class Report(QueueResource):
    """ Resource to accessed finished reports """
    def get(self, job_id):
        """ Unless a Cuckoo report is placed in
        storage/analyses/0/reports/report.json this returns minimal report """
        filename = 'storage/analyses/0/reports/report.json'
        try:
            with open(filename, 'r') as content_file:
                report = json.load(content_file)
        except FileNotFoundError:
            report = {
                "info": {
                    "score": 10,
                    "id": int(job_id),
                },
                "signatures": [
                    {
                        "description":
                            "Malicious document featuring Office "
                            "DDE has been identified",
                    }
                ],
                "debug": {
                    "cuckoo": [
                        "analysis completed successfully",
                    ],
                },
            }

        return flask.jsonify(report)


class Create(QueueResource):
    """ Resource to post sample for analysis """
    def post(self):
        """ Doesn't do anything with the data sent. """
        print(flask.request.files)
        job_id = self.queue.register_job()
        result = {'task_id': job_id}
        return flask.jsonify(result)


def run():
    """ Run the API """
    app = flask.Flask(__name__)
    app.debug = True
    api = flask_restful.Api(app)

    queue = Queue()

    api.add_resource(Status, '/cuckoo/status', resource_class_args=[queue])
    api.add_resource(View, '/tasks/view/<job_id>', resource_class_args=[queue])
    api.add_resource(Report, '/tasks/report/<job_id>',
                     resource_class_args=[queue])
    api.add_resource(Create, '/tasks/create/file', resource_class_args=[queue])

    app.run(port='5002')


if __name__ == '__main__':
    sys.exit(run())
