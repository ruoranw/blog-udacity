import os
import re
import random
import hashlib
import hmac
import time

from string import letters

import jinja2
import webapp2

from google.appengine.ext import db

# create a jinja environment
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

file = open('secret.txt', 'r')
secret = file.read()

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

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

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
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

class MainPage(Handler):
    def get(self):
        self.write("Welcome to Ruoran's Blog Website!")

# user datastore
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
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

# signup
# regex
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignUp(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

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
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(SignUp):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')

# blog stuff
# define a parent key for blogs
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# database
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author_id = db.IntegerProperty(required=True)
    liked = db.ListProperty(int, required=True)

    @classmethod
    def by_id(cls, pid):
    # retrieves the model instance for the given numeric ID
        return Post.get_by_id(pid, parent = blog_key())

    def render(self, user, permalink):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("post.html", p = self, user = user,
                          author = User.by_id(int(self.author_id)),
                          permalink = permalink)

# comment
class Comment(db.Model):
    author_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    content = db.TextProperty(required = True)
    liked = db.ListProperty(int, required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, pid):
        return Comment.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("comment.html", c=self, user=user,
                          author=User.by_id(int(self.author_id)))

class BlogFront(Handler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts, user = self.user)

class NewPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        comments = Comment.all().filter(
            'post_id =', int(post_id)).order('created')

        self.render("permalink.html", post = post, comments = comments)

class PostPage(Handler):
    def get(self):
        if self.user:
            self.render("postpage.html")
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Post(parent = blog_key(), subject = subject,
                     content = content, author_id = self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "We need some subjects and contents!"
            self.render("postpage.html", subject = subject, content = content, error = error)


class EditPost(Handler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render('editpost.html', post = post)

        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.author_id != self.user.key().id():
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content

            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", post=post,
                        error=error)

class DeletePost(Handler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("deletepost.html", post=post)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.author_id != self.user.key().id():
            self.redirect("/blog")

        post.delete()
        time.sleep(0.25)
        self.redirect('/blog')

class NewComment(Handler):
    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        content = self.request.get('content')

        if post_id and content:
            c = Comment( post_id = post_id, content = content,
                        author_id = self.user.key().id(), parent = blog_key())
            c.put()

        self.redirect('/blog/%s' % str(post_id))


class EditComment(Handler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("editcomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
            self.redirect("/blog")

        content = self.request.get('content')

        if content:
            comment.content = content
            comment.put()
            self.redirect('/blog/%s' % str(comment.post_id))
        else:
            error = "content, please!"
            self.render("editcomment.html", comment=comment, error=error)


class DeleteComment(Handler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("deletecomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
                self.redirect("/blog")

        comment.delete()
        time.sleep(0.25)
        self.redirect('/blog/%s' % str(comment.post_id))

class Like(Handler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid != item.author_id and uid not in item.liked:
                item.liked.append(uid)
                item.put()
                time.sleep(0.25)

            if self.request.get('permalink') == 'True':
                self.redirect('/blog/%s' % str(post_id))
            else:
                self.redirect('/blog')

        else:
            self.redirect("/login")


class Dislike(Handler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid in item.liked:
                item.liked.remove(uid)
                item.put()
                time.sleep(0.25)

            if self.request.get('permalink') == 'True':
                self.redirect('/blog/%s' % str(post_id))
            else:
                self.redirect('/blog')
        else:
            self.redirect("/login")


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog', BlogFront),
    ('/blog/newpost', PostPage),
    ('/blog/newcomment', NewComment),
    ('/blog/editcomment', EditComment),
    ('/blog/deletecomment', DeleteComment),
    ('/blog/like', Like),
    ('/blog/dislike', Dislike),
    ('/blog/([0-9]+)', NewPost),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog/editpost', EditPost),
    ('/blog/deletepost', DeletePost)
], debug=True)
