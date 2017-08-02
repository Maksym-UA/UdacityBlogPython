#!/usr/bin/python
# -*- coding: utf-8 -*-

# import google Gcloud database

from google.appengine.ext import db

from user_model import User


def blog_key(name='default'):  # defines blog object parent
    return db.Key.from_path('blogs', name)


class MyBlog(db.Model):

    '''
    Class responsible for initiating and storing post entities.
    '''

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    # set reference to User

    author = db.ReferenceProperty(User, collection_name='author')
    likes = db.IntegerProperty()
    users_liked = db.StringListProperty()

    # render blog entry and replace newlines in html line breaks

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('newpost.html', p=self)

    @classmethod
    def by_id(cls, uid):
        return MyBlog.get_by_id(uid, parent=blog_key())

    @property
    def post_likes(self):
        return len(self.users_liked)
