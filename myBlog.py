import os
import webapp2
import jinja2
import re
import random
import hashlib
import hmac
from string import letters
import time



from google.appengine.ext import db

#show path where templates are stored
template_dir = os.path.join(os.path.dirname(__file__), 'templates_for_blog')

#set jinja environment
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)#for html tags to be read as text, not code

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
    def write(self, *a, **kw):#multiple parameters that can be added
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):#method to render page by jinja
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):#method to call rendered page
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
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

    def initialize(self, *a, **kw):
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

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


class User(db.Model):
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


def blog_key(name = 'default'):#defines object parent
    return db.Key.from_path('blogs', name)

class myBlog(db.Model):#to store all newposts
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
    #define number of entries displayed per page
##    def render_index_page(self):
##        allposts = db.GqlQuery(
##            'SELECT * FROM myBlog ORDER BY created DESC LIMIT 10')
##        self.render('index.html', allposts = allposts)

        
    def get(self):
        allposts = greetings = myBlog.all().order('-created')       
        self.render('index.html', allposts = allposts )

    def post(self):
        postid = self.request.get('post_id_to_edit')
        post_to_delete = self.request.get('post_id_to_delete')
        post_to_like = self.request.get('post_id_to_like')

        if postid:
            self.redirect('/blog/post%s' % str(postid))
            
        if post_to_delete:
            key = db.Key.from_path('myBlog', int(post_to_delete), parent=blog_key())
            post = db.get(key)
            post.delete()
            self.redirect('/blog')

        if post_to_like:
            key = db.Key.from_path('myBlog', int(post_to_like), parent=blog_key())
            post = db.get(key)

            if self.user:                
                if self.user.key().id()!= post.user_id and self.user.name not in post.users_liked:
                    post.users_liked.append(self.user.name)
                    post.likes += 1
                    post.put()
                    time.sleep(0.1)
                self.redirect('/blog')

##                else:
##                    login_error = "One like per user"
##                    self.render('index.html', login_error = login_error )
            else:
                self.redirect('/blog/login')
                return

            
##class PostLikes(Handler):
##    def post(self, post_id):
##        key = db.Key.from_path('myBlog', int(post_id), parent=blog_key())
##        post = db.get(key)
##
##        if self.user:
##            if self.user.key().id()!= post.user_id:
##                post.users_liked.append(self.user.name)
##                post.likes += 1
##                post.put()
##                time.sleep(0.1)
##                self.redirect('/blog')
##        else:
##            self.redirect('/blog/login')
##            return


class PostPage(Handler):
    #display the last entry to the blog and direct to its' own link
    def get(self, post_id):
        key = db.Key.from_path('myBlog', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post = post)


class NewPost(Handler):
    
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
            p = myBlog(parent = blog_key(), subject = subject, content = content, user_id = user_id, likes = 0)
            p.put()#store created object in the database
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'subject and content, please!'
            self.render('newpost.html', subject=subject, content=content, error=error)
            

class EditPost(Handler):

    def get(self, post_id):
        key = db.Key.from_path('myBlog', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if self.user:
            self.render('editpost.html', postid = post_id, post = post)
        else:
            self.redirect('/blog/login')

    def post(self, post_id):
        key = db.Key.from_path('myBlog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if content:
            post.content = content
            post.put()#store edited object in the database
            self.redirect('/blog')     
            

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r'^.{3,20}$')
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):
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
    def get(self):
        self.logout()
        self.redirect('/blog/login')
        

class Welcome(Handler):
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
    #('/blog/newlike([0-9]+)', PostLikes),
    ],
                              debug=True)
