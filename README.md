# DSCsrf  
  
Very simple and (almost) plug-and-play global CSRF filtering for Flask using the Double Submit technique outlined on OWASP at https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookies.  
  
How to use:  
  
    from dscsrf import Csrf
    from flask import Flask
    
    app = Flask(__name__)
    
    csrf = Csrf(app)

and that's it!  
  
For rendering the CSRF token in your application, under your form HTML use:  
  
    {{ csrf_token() }}