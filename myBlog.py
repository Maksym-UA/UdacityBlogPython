#This module provides a portable way of using operating system functionality.
import os
#lightweight Python web framework compatible with Google App Engine
import webapp2
# templating language for Python
import jinja2
#This module provides regular expression matching operations
import re
import random
#his module implements a common interface to many different
#secure hash and message digest algorithms
import hashlib
#This module implements the HMAC algorithm
import hmac
from string import letters
import time

#import google Gcloud database
from google.appengine.ext import db

#show path where templates are stored
template_dir = os.path.join(os.path.dirname(__file__), 'templates_for_blog')

#set jinja environment
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
                               #for html tags to be read as text, not code
#set secret key for encrypting password
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
    def write(self, *a, **kw):#multiple parameters that can be added
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):#method to render page by jinja
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):#method to call rendered page
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):#initially cookie for a user
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):#verify 'correct' user logged in
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):#defines user object parent
    return db.Key.from_path('users', group)


class User(db.Model):
    '''
    This class is responsible for creating user entities in the database.
    '''
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod#decorator
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name = 'default'):#defines blog object parent
    return db.Key.from_path('blogs', name)


class MyBlog(db.Model):
    '''
    Class responsible for initiating and storing post entities.
    '''
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty()
    likes = db.IntegerProperty()
    users_liked = db.StringListProperty()

    #render blog entry and replace newlines in html line breaks
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('newpost.html', p = self)


class FrontPage(Handler):
    '''
    Class for rendering homepage of the blog.
    '''
    #define number of entries displayed per page
##    def render_index_page(self):
##        allposts = db.GqlQuery(
##            'SELECT * FROM MyBlog ORDER BY created DESC LIMIT 10')
##        self.render('index.html', allposts = allposts)


    def get(self):
        allposts = MyBlog.all().order('-created')
        allcomments = Comment.all()
        self.render('index.html', allposts = allposts,
                    allcomments = allcomments)

    def post(self):
        post_id_to_edit = self.request.get('post_id_to_edit')
        post_to_delete = self.request.get('post_id_to_delete')
        post_to_like = self.request.get('post_id_to_like')
        post_to_unlike = self.request.get('post_id_to_unlike')
        post_to_comment = self.request.get('post_to_comment')

        comment_id_to_edit = self.request.get('comment_id_to_edit')
        comment_id_to_delete = self.request.get('comment_id_to_delete')

        allposts = MyBlog.all().order('-created')
        allcomments = Comment.all()

        if post_id_to_edit:
            self.redirect('/blog/post%s' % str(post_id_to_edit))

        if post_to_delete:
            key = db.Key.from_path('MyBlog', int(post_to_delete),
                                    parent=blog_key())
            post = db.get(key)
            post.delete()
            self.redirect('/blog')

        if post_to_like:
            key = db.Key.from_path('MyBlog', int(post_to_like),
                                    parent=blog_key())
            post = db.get(key)

            if self.user:
                userid = self.user.key().id()
                username = self.user.name
                if userid != post.user_id and username not in post.users_liked:
                    post.users_liked.append(username)
                    post.likes += 1
                    post.put()
                    time.sleep(0.1)
                self.redirect('/blog')
            else:

                postide = post.key().id()
                error = 'Login, please!'
                self.render('index.html', allposts = allposts,
                            allcomments = allcomments,
                            error=error, postide = postide)

        if post_to_unlike:
            key = db.Key.from_path('MyBlog', int(post_to_unlike),
                                    parent=blog_key())
            post = db.get(key)

            if self.user:
                if self.user.name in post.users_liked:
                    post.users_liked.remove(self.user.name)
                    post.likes -= 1
                    post.put()
                    time.sleep(0.1)
                self.redirect('/blog')
            else:

                postide = post.key().id()
                error = 'Login, please!'
                self.render('index.html', allposts = allposts,
                            allcomments = allcomments,
                            error=error, postide = postide)
        if post_to_comment:
           self.redirect('/blog/post%s/comment'% str(post_to_comment))

        if comment_id_to_edit:
            self.redirect('/blog/comment%s' % str(comment_id_to_edit))

        if comment_id_to_delete:
            key = db.Key.from_path('Comment', int(comment_id_to_delete),
                                    parent=comment_key())
            comment = db.get(key)
            comment.delete()
            self.redirect('/blog')


class PostPage(Handler):
    '''
    Class responsible for displayin the last entry to the blog and
    directin to its' own link.
    '''
    def get(self, post_id):
        key = db.Key.from_path('MyBlog', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render('permalink.html', post = post)


class NewPost(Handler):
    '''
    Class to create new post entities.
    '''
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/blog/login')

    def post(self):#fetch data inputs from the user
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        user_id = self.user.key().id()

        if subject and content:
            p = MyBlog(parent = blog_key(), subject = subject,
                        content = content, user_id = user_id, likes = 0)
            p.put()#store created object in the database
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Subject and content, please!'
            self.render('newpost.html', subject=subject,
                        content=content, error=error)


class EditPost(Handler):
    '''
    Class for editin selected post content.
    '''
    def get(self, post_id):
        key = db.Key.from_path('MyBlog', int(post_id), parent=blog_key())
        post = db.get(key)
        content = post.content

        if self.user:
            self.render('editpost.html', postid = post_id, content = content)
        else:
            self.redirect('/blog/login')

    def post(self, post_id):
        key = db.Key.from_path('MyBlog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect('/blog')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if content:
                post.content = content
                post.put()#store edited object in the database
                self.redirect('/blog')
            else:
                error = 'Content, please!'
                self.render('editpost.html', content=content, error=error)


def comment_key(name = 'default'):#defines comment object parent
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    '''
    Class for initiating new entities of comments.
    '''
    comment_text = db.TextProperty(required=True)
    comment_author = db.StringProperty()
    post_commented = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now = True)



class NewComment(Handler):
    '''
    Class for creating new comment entities.
    '''
    def get(self, post_to_comment):
        key = db.Key.from_path('MyBlog', int(post_to_comment),
                                parent=blog_key())
        post = db.get(key)
        if self.user:
            self.render('newcomment.html', post = post)
        else:
            self.redirect('/blog/login')

    def post(self, post_to_comment):#fetch data inputs from the user
        key = db.Key.from_path('MyBlog', int(post_to_comment),
                                parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect('/blog')

        comment_author = self.user.name
        comment_text = self.request.get('comment')
        post_commented = int(post_to_comment)

        if comment_text:
            c = Comment(parent = comment_key(), comment_text = comment_text,
                        comment_author = comment_author,
                        post_commented = post_commented)
            c.put()#store created object in the database
            self.redirect('/blog')
        else:
            error = 'Add content, please!'
            self.render('newcomment.html', post = post, error=error)


class EditComment(Handler):
    '''
    Class for editing selected comment content.
    '''
    def get(self, comment_id_to_edit):
            key = db.Key.from_path('Comment', int(comment_id_to_edit),
                                    parent=comment_key())
            comment = db.get(key)
            comment_text = comment.comment_text

            if self.user:
                self.render('editcomment.html',
                            comment_id_to_edit = comment_id_to_edit,
                            comment_text = comment_text)
            else:
                self.redirect('/blog/login')

    def post(self, comment_id_to_edit):
        key = db.Key.from_path('Comment', int(comment_id_to_edit),
                                parent=comment_key())
        comment = db.get(key)
        content = self.request.get('comment_text')

        if not self.user:
            self.redirect('/blog')

        if content:
            comment.comment_text = content
            comment.put()#store edited object in the database
            self.redirect('/blog')
        else:
            error = 'Content, please!'
            self.render('editcomment.html', content=content, error=error)

#verify username is of proper form
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
    return username and USER_RE.match(username)

#verify password is of proper form
PASS_RE = re.compile(r'^.{3,20}$')
def valid_password(password):
    return password and PASS_RE.match(password)

#verify email is of proper form
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
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

        params = dict(username = self.username,
                      email = self.email)

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
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
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

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/user%s' % str(u.key().id()))
        else:
            verify_error = 'Invalid login'
            self.render('login.html', verify_error = verify_error)


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
        key = db.Key.from_path('User', int(user_id), parent = users_key())
        user = db.get(key)
        username = user.name

        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

app = webapp2.WSGIApplication([
    ('/blog/signup', Register),
    ('/blog/user([0-9]+)', Welcome),#let pass any interger like object.id
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog', FrontPage),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/post([0-9]+)', EditPost),
    ('/blog/post([0-9]+)/comment', NewComment),
    ('/blog/comment([0-9]+)', EditComment),
    ],
                              debug=True)
