#!/usr/bin/python
# -*- coding: utf-8 -*-
# import google Gcloud database

from google.appengine.ext import db


def comment_key(name='default'):  # defines comment object parent
    return db.Key.from_path('comments', name)


class Comment(db.Model):

    '''
    Class for initiating new entities of comments.
    '''

    comment_text = db.TextProperty(required=True)
    comment_author = db.StringProperty()
    post_commented = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now=True)

    @classmethod # find comment by its id
    def by_id(cls, cid):
        return Comment.get_by_id(cid, parent=comment_key())

