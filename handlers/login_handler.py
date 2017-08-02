import sys
sys.path.insert(0, 'C:\Users\M\Desktop\UDACITY\WebApplication and Development\bloproject')

from bloproject import *


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
