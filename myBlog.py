#!/usr/bin/python
# -*- coding: utf-8 -*-

# This module provides a portable way of using operating system functionality.

import os

# This module provides regular expression matching operations

import re
import random

# this module implements a common interface to many different
# secure hash and message digest algorithms

import hashlib

# This module implements the HMAC algorithm

import hmac
from string import letters
import time

# lightweight Python web framework compatible with Google App Engine

import webapp2

# templating language for Python

import jinja2

# import google Gcloud database

from google.appengine.ext import db

from functools import wraps

# import entitied model handlers

from models import comments_model, blog_model, user_model

# show path where templates are stored

template_dir = os.path.join(os.path.dirname(__file__),
                            'templates_for_blog')

# set jinja environment

jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)

# for html tags to be read as text, not code
# set secret key for encrypting password

secret = 'topsecret'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):

    '''
    This class sets handler render methods and also is responsible for secure
    authorization of users.
    '''

    def write(self, *a, **kw):  # multiple parameters that can be added
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):  # method to render page by jinja
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):  # method to call rendered page
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):  # initially cookie for a user
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

    def initialize(self, *a, **kw):  # verify 'correct' user logged in
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and user_model.User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class FrontPage(Handler):

    '''
    Class for rendering homepage of the blog.
    '''

    def get(self):
        allposts = blog_model.MyBlog.all().order('-created')
        allcomments = comments_model.Comment.all()
        self.render('index.html', allposts=allposts,
                    allcomments=allcomments)

    def post(self):
        post_to_delete = self.request.get('post_id_to_delete')
        comment_id_to_delete = self.request.get('comment_id_to_delete')

        allposts = blog_model.MyBlog.all().order('-created')
        allcomments = comments_model.Comment.all()

        if self.user:
            if post_to_delete:
                key = db.Key.from_path('MyBlog', int(post_to_delete),
                                       parent=blog_model.blog_key())
                post = db.get(key)
                post.delete()
                self.redirect('/blog')

            if comment_id_to_delete:
                key = db.Key.from_path('Comment',
                                       int(comment_id_to_delete),
                                       parent=comments_model.comment_key())
                comment = db.get(key)
                comment.delete()
        else:
            self.redirect('/blog/login')
            return


class LikeHandler(Handler):

    '''
    Class for adding/subtracting likes of the post.
    '''

    def get(self, post_id):
        key = db.Key.from_path('MyBlog', int(post_id),
                               parent=blog_model.blog_key())
        post = db.get(key)
        self.render('likes.html', post=post)

    def post(self, post_id):
        post_to_like = self.request.get('post_id_to_like')
        post_to_unlike = self.request.get('post_id_to_unlike')

        if self.user:
            username = self.user.name
            if post_to_like:
                key = db.Key.from_path('MyBlog', int(post_to_like),
                                       parent=blog_model.blog_key())
                post = db.get(key)
                if (username != post.author.name and username
                        not in post.users_liked):
                        post.users_liked.append(username)
                        post.put()
                        time.sleep(0.1)
                self.redirect('/blog')
            if post_to_unlike:
                key = db.Key.from_path('MyBlog', int(post_to_unlike),
                                       parent=blog_model.blog_key())
                post = db.get(key)
                if self.user.name in post.users_liked:
                    post.users_liked.remove(self.user.name)
                    post.put()
                    time.sleep(0.1)
                self.redirect('/blog')
        else:
            logerror = 'Login, please!'
            self.render('index.html', error=error)
            return


class PostPage(Handler):

    '''
    Class responsible for displayin the last entry to the blog and
    directin to its' own link.
    '''

    def get(self, post_id):
        key = db.Key.from_path('MyBlog', int(post_id),
                               parent=blog_model.blog_key())
        post = db.get(key)
        author = post.author.name

        if not post:
            self.error(404)
            return
        self.render('permalink.html', post=post)


class NewPost(Handler):

    '''
    Class to create new post entities.
    '''

    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/blog/login')

    def post(self):  # fetch data inputs from the user
        if not self.user:
            self.redirect('/blog/login')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')
        # set reference to User object as post author
        user = user_model.User.by_name(self.user.name)
        user_name = user.name

        if subject and content:
            p = blog_model.MyBlog(parent=blog_model.blog_key(),
                                  author=user, subject=subject,
                                  content=content, likes=0)
            p.put()  # store created object in the database
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Subject and content, please!'
            self.render('newpost.html', subject=subject,
                        content=content, error=error)


class EditPost(Handler):

    '''
    Class for editing selected post content.
    '''

    # decorator to verify the required post actually exists

    def post_valid(func):

        @wraps(func)
        def wrapper(self, post_id):
            key = db.Key.from_path('MyBlog', int(post_id),
                                   parent=blog_model.blog_key())
            post = db.get(key)
            if post:
                return func(self, post_id)
            else:
                self.error(404)
                return
        return wrapper

    @post_valid
    def get(self, post_id):
        if self.user:
            post = blog_model.MyBlog.by_id(int(post_id))
            if self.user.name == post.author.name:  # verify post owner
                content = post.content
            self.render('editpost.html', postid=post_id,
                        content=content)
        else:
            self.redirect('/blog/login')
            return

    @post_valid
    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
            return
        else:
            post = blog_model.MyBlog.by_id(int(post_id))
            subject = self.request.get('subject')
            content = self.request.get('content')
            if content:
                post.content = content
                post.put()  # store edited object in the database
                self.redirect('/blog')
            else:
                error = 'Content, please!'
                self.render('editpost.html', content=content,
                            error=error)


class NewComment(Handler):

    '''
    Class for creating new comment entities.
    '''

    def get(self, post_to_comment):
        key = db.Key.from_path('MyBlog', int(post_to_comment),
                               parent=blog_model.blog_key())
        post = db.get(key)
        if self.user:
            self.render('newcomment.html', post=post)
        else:
            self.redirect('/blog/login')

    def post(self, post_to_comment):  # fetch data inputs from the user
        key = db.Key.from_path('MyBlog', int(post_to_comment),
                               parent=blog_model.blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect('/blog')
            return

        comment_author = self.user.name
        comment_text = self.request.get('comment')
        post_commented = int(post_to_comment)

        if comment_text:
            c = comments_model.Comment(parent=comments_model.comment_key(),
                                       comment_text=comment_text,
                                       comment_author=comment_author,
                                       post_commented=post_commented)
            c.put()  # store created object in the database
            self.redirect('/blog')
        else:
            error = 'Add content, please!'
            self.render('newcomment.html', post=post, error=error)


class EditComment(Handler):

    '''
    Class for editing selected comment content.
    '''

    # decorator to verify the required comment actually exists

    def comment_valid(func):

        @wraps(func)
        def wrapper(self, comment_id_to_edit):
            key = db.Key.from_path('Comment', int(comment_id_to_edit),
                                   parent=comments_model.comment_key())
            post = db.get(key)
            if post:
                return func(self, comment_id_to_edit)
            else:
                self.error(404)
                return
        return wrapper

    @comment_valid
    def get(self, comment_id_to_edit):
        if self.user:
            comment = \
                comments_model.Comment.by_id(int(comment_id_to_edit))
            comment_text = comment.comment_text
            self.render('editcomment.html',
                        comment_id_to_edit=comment_id_to_edit,
                        comment_text=comment_text)
        else:
            self.redirect('/blog/login')
            return

    def post(self, comment_id_to_edit):
        comment = comments_model.Comment.by_id(int(comment_id_to_edit))
        content = self.request.get('comment_text')

        if not self.user:
            self.redirect('/blog')
            return

        if self.user.name == comment.comment_author:  # verify comment owner
            if content:
                comment.comment_text = content
                comment.put()  # store edited object in the database
                self.redirect('/blog')
            else:
                error = 'Content, please!'
                self.render('editcomment.html', content=content,
                            error=error)


# verify username is of proper form

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')


def valid_username(username):
    return username and USER_RE.match(username)


# verify password is of proper form

PASS_RE = re.compile(r'^.{3,20}$')


def valid_password(password):
    return password and PASS_RE.match(password)


# verify email is of proper form

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(Handler):

    '''
    Class to verify data inputs from signup page and register new users.
    '''

    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    '''
    Class responsible for making sure new user is unique.
    '''

    def done(self):

        # make sure the user doesn't already exist

        u = user_model.User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = user_model.User.register(self.username,
                                         self.password,
                                         self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')


class Login(Handler):

    '''
    Class for rendering login page and let valid users login.
    '''

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # u_type_input = ('%s - %s' % (type(str(username)) ,username))
        # p_type_input = ('%s - %s' % (type(str(password)) , password))

        u = user_model.User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/user%s' % str(u.key().id()))
        else:
            verify_error = 'Invalid login'
            self.render('login.html', verify_error=verify_error)


class Logout(Handler):

    '''
    Class for succeful signing out of users.
    '''

    def get(self):
        self.logout()
        self.redirect('/blog/signup')


class Welcome(Handler):

    '''
    Class for greeting succefully logged in user.
    '''

    def get(self, user_id):
        key = db.Key.from_path('User', int(user_id),
                               parent=user_model.users_key())
        user = db.get(key)
        username = user.name

        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')


app = webapp2.WSGIApplication([  # let pass any interger like object.id
    ('/blog/signup', Register),
    ('/blog/user([0-9]+)', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog', FrontPage),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/post([0-9]+)', EditPost),
    ('/blog/post([0-9]+)/comment', NewComment),
    ('/blog/comment([0-9]+)', EditComment),
    ('/blog/like/([0-9]+)', LikeHandler),
    ], debug=True)
